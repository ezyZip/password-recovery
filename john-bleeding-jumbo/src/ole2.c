/*
 * ole2.c — minimal read-only OLE2 / CFB reader. See ole2.h.
 *
 * Implements just enough of MS-CFB to enumerate directory entries and read
 * named streams (via the FAT for >=4096-byte streams, the mini-FAT otherwise).
 * Every sector index and file offset is bounds-checked and chain walks are
 * iteration-capped, so corrupt input fails cleanly (NULL) rather than crashing.
 */
#include <stdlib.h>
#include <string.h>
#include "ole2.h"

#define FREESECT   0xFFFFFFFFu
#define ENDOFCHAIN 0xFFFFFFFEu
#define FATSECT    0xFFFFFFFDu
#define DIFSECT    0xFFFFFFFCu

struct ole_file {
	const uint8_t *buf;
	size_t   len;
	uint32_t sector_size;
	uint32_t mini_sector_size;
	uint32_t mini_cutoff;
	uint32_t *fat;        size_t fat_count;
	uint32_t *minifat;    size_t minifat_count;
	ole_entry *dir;       size_t dir_count;
	ole_entry  root;
	uint8_t   *ministream; size_t ministream_len;
};

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd64(const uint8_t *p)
{
	return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

/* file offset of sector s, or (size_t)-1 if out of range */
static size_t sector_off(const ole_file *f, uint32_t s)
{
	size_t off;
	if (s >= 0xFFFFFFFAu) return (size_t)-1;          /* sentinel range */
	off = 512 + (size_t)s * f->sector_size;
	if (off + f->sector_size > f->len) return (size_t)-1;
	return off;
}

/* Walk a sector chain starting at `start` through `fat`, appending each
 * sector's `chunk` bytes to *out (realloc'd). Returns total bytes, or
 * (size_t)-1 on corruption. Caps iterations to fat_count to break cycles. */
static size_t read_chain(const ole_file *f, const uint32_t *fat, size_t fat_count,
                         uint32_t start, uint32_t chunk, uint8_t **out)
{
	uint8_t *buf = NULL;
	size_t total = 0, steps = 0;
	uint32_t s = start;

	while (s != ENDOFCHAIN && s != FREESECT) {
		size_t off;
		uint8_t *nb;
		if (s >= fat_count) { free(buf); return (size_t)-1; }
		if (++steps > fat_count + 1) { free(buf); return (size_t)-1; }  /* cycle */
		off = sector_off(f, s);
		if (off == (size_t)-1) { free(buf); return (size_t)-1; }
		nb = realloc(buf, total + chunk);
		if (!nb) { free(buf); return (size_t)-1; }
		buf = nb;
		memcpy(buf + total, f->buf + off, chunk);
		total += chunk;
		s = fat[s];
	}
	*out = buf;
	return total;
}

static int parse_header(ole_file *f)
{
	static const uint8_t sig[8] = { 0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1 };
	uint16_t ssh, mssh;

	if (f->len < 512 || memcmp(f->buf, sig, 8)) return 0;
	ssh  = rd16(f->buf + 0x1E);
	mssh = rd16(f->buf + 0x20);
	if (ssh != 9 && ssh != 12) return 0;              /* 512 or 4096 */
	if (mssh != 6) return 0;                          /* 64-byte mini sectors */
	f->sector_size = 1u << ssh;
	f->mini_sector_size = 1u << mssh;
	f->mini_cutoff = rd32(f->buf + 0x38);
	if (f->mini_cutoff == 0) f->mini_cutoff = 4096;
	if (f->len < 512u + f->sector_size && f->sector_size > 512) {
		/* a 4096-sector file must hold at least the first sector after header */
	}
	return 1;
}

/* Build the full FAT array from the DIFAT (109 header entries + DIFAT chain). */
static int build_fat(ole_file *f)
{
	uint32_t num_fat = rd32(f->buf + 0x2C);
	uint32_t difat_start = rd32(f->buf + 0x44);
	uint32_t num_difat = rd32(f->buf + 0x48);
	uint32_t per = f->sector_size / 4;
	uint32_t *fatsectors;
	size_t nfs = 0, cap;
	uint32_t i, s, guard;

	if (num_fat == 0 || num_fat > (f->len / f->sector_size) + 2) return 0;
	cap = num_fat + 8;
	fatsectors = malloc(cap * sizeof(uint32_t));
	if (!fatsectors) return 0;

	/* 109 DIFAT entries live in the header at 0x4C */
	for (i = 0; i < 109 && nfs < num_fat; i++) {
		uint32_t v = rd32(f->buf + 0x4C + 4 * i);
		if (v == FREESECT || v >= 0xFFFFFFFAu) continue;
		if (nfs < cap) fatsectors[nfs++] = v;
	}
	/* follow the DIFAT sector chain for the rest */
	s = difat_start; guard = 0;
	while (s != ENDOFCHAIN && s != FREESECT && nfs < num_fat &&
	       guard++ <= num_difat + 1) {
		size_t off = sector_off(f, s);
		uint32_t j;
		if (off == (size_t)-1) { free(fatsectors); return 0; }
		for (j = 0; j < per - 1 && nfs < num_fat; j++) {
			uint32_t v = rd32(f->buf + off + 4 * j);
			if (v == FREESECT || v >= 0xFFFFFFFAu) continue;
			if (nfs >= cap) { cap *= 2; uint32_t *nn = realloc(fatsectors, cap * sizeof(uint32_t));
			                  if (!nn) { free(fatsectors); return 0; } fatsectors = nn; }
			fatsectors[nfs++] = v;
		}
		s = rd32(f->buf + off + 4 * (per - 1));        /* next DIFAT sector */
	}

	f->fat_count = (size_t)nfs * per;
	f->fat = malloc(f->fat_count * sizeof(uint32_t));
	if (!f->fat) { free(fatsectors); return 0; }
	for (i = 0; i < nfs; i++) {
		size_t off = sector_off(f, fatsectors[i]);
		uint32_t j;
		if (off == (size_t)-1) { free(fatsectors); return 0; }
		for (j = 0; j < per; j++)
			f->fat[(size_t)i * per + j] = rd32(f->buf + off + 4 * j);
	}
	free(fatsectors);
	return 1;
}

static int build_minifat(ole_file *f)
{
	uint32_t start = rd32(f->buf + 0x3C);
	uint32_t num = rd32(f->buf + 0x40);
	uint8_t *raw = NULL;
	size_t got;

	if (num == 0 || start == ENDOFCHAIN) { f->minifat = NULL; f->minifat_count = 0; return 1; }
	got = read_chain(f, f->fat, f->fat_count, start, f->sector_size, &raw);
	if (got == (size_t)-1) return 0;
	f->minifat_count = got / 4;
	f->minifat = malloc((f->minifat_count ? f->minifat_count : 1) * sizeof(uint32_t));
	if (!f->minifat) { free(raw); return 0; }
	for (size_t i = 0; i < f->minifat_count; i++)
		f->minifat[i] = rd32(raw + 4 * i);
	free(raw);
	return 1;
}

static void fold_name(const uint8_t *p, uint16_t name_len_bytes, char *out)
{
	uint32_t chars = name_len_bytes >= 2 ? (uint32_t)(name_len_bytes / 2 - 1) : 0;
	uint32_t i;
	if (chars > 31) chars = 31;
	for (i = 0; i < chars; i++)
		out[i] = (char)p[i * 2];                       /* low byte of UTF-16LE */
	out[i] = '\0';
}

static int build_directory(ole_file *f)
{
	uint32_t dir_start = rd32(f->buf + 0x30);
	uint8_t *raw = NULL;
	size_t got, n, i;

	got = read_chain(f, f->fat, f->fat_count, dir_start, f->sector_size, &raw);
	if (got == (size_t)-1) return 0;
	n = got / 128;
	f->dir = calloc(n ? n : 1, sizeof(ole_entry));
	if (!f->dir) { free(raw); return 0; }
	f->dir_count = 0;
	memset(&f->root, 0, sizeof(f->root));

	for (i = 0; i < n; i++) {
		const uint8_t *e = raw + i * 128;
		uint16_t nl = rd16(e + 0x40);
		uint8_t  type = e[0x42];
		if (type != 1 && type != 2 && type != 5) continue;
		ole_entry ent;
		memset(&ent, 0, sizeof(ent));
		fold_name(e, nl, ent.name);
		ent.type = type;
		ent.start = rd32(e + 0x74);
		ent.size = rd64(e + 0x78);
		if (type == 5) f->root = ent;                  /* root: mini-stream container */
		f->dir[f->dir_count++] = ent;
	}
	free(raw);
	return 1;
}

/* Materialize the mini-stream (root entry's chain in the regular FAT). */
static int build_ministream(ole_file *f)
{
	uint8_t *raw = NULL;
	size_t got;
	if (f->root.type != 5 || f->root.size == 0) { f->ministream = NULL; f->ministream_len = 0; return 1; }
	got = read_chain(f, f->fat, f->fat_count, f->root.start, f->sector_size, &raw);
	if (got == (size_t)-1) return 0;
	f->ministream = raw;
	f->ministream_len = got;
	return 1;
}

ole_file *ole_open(const uint8_t *buf, size_t len)
{
	ole_file *f = calloc(1, sizeof(*f));
	if (!f) return NULL;
	f->buf = buf;
	f->len = len;
	if (!parse_header(f) || !build_fat(f) || !build_minifat(f) ||
	    !build_directory(f) || !build_ministream(f)) {
		ole_close(f);
		return NULL;
	}
	return f;
}

const ole_entry *ole_find_stream(ole_file *f, const char *name)
{
	size_t i;
	if (!f) return NULL;
	for (i = 0; i < f->dir_count; i++)
		if (f->dir[i].type == 2 && !strcmp(f->dir[i].name, name))
			return &f->dir[i];
	return NULL;
}

uint8_t *ole_read_stream(ole_file *f, const ole_entry *e, size_t *out_len)
{
	uint8_t *out;
	size_t want;
	if (!f || !e) return NULL;
	want = (size_t)e->size;

	if (e->size >= f->mini_cutoff) {
		/* large stream: regular FAT, sector_size chunks */
		uint8_t *raw = NULL;
		size_t got = read_chain(f, f->fat, f->fat_count, e->start, f->sector_size, &raw);
		if (got == (size_t)-1) return NULL;
		out = malloc(want ? want : 1);
		if (!out) { free(raw); return NULL; }
		memcpy(out, raw, want < got ? want : got);
		free(raw);
	} else {
		/* small stream: mini-FAT, mini-sector chunks sliced from the ministream */
		uint32_t s = e->start, steps = 0;
		size_t o = 0;
		out = malloc(want ? want : 1);
		if (!out) return NULL;
		while (s != ENDOFCHAIN && s != FREESECT && o < want) {
			size_t mo = (size_t)s * f->mini_sector_size;
			size_t n = f->mini_sector_size;
			if (s >= f->minifat_count) { free(out); return NULL; }
			if (++steps > f->minifat_count + 1) { free(out); return NULL; }  /* cycle */
			if (mo + n > f->ministream_len) { free(out); return NULL; }
			if (n > want - o) n = want - o;
			memcpy(out + o, f->ministream + mo, n);
			o += n;
			s = f->minifat[s];
		}
		if (o < want) memset(out + o, 0, want - o);
	}
	*out_len = want;
	return out;
}

size_t ole_num_entries(const ole_file *f) { return f ? f->dir_count : 0; }
const ole_entry *ole_entry_at(const ole_file *f, size_t i)
{
	return (f && i < f->dir_count) ? &f->dir[i] : NULL;
}

void ole_close(ole_file *f)
{
	if (!f) return;
	free(f->fat);
	free(f->minifat);
	free(f->dir);
	free(f->ministream);
	free(f);
}
