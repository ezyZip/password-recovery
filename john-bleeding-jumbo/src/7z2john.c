/*
 * 7z2john.c — C port of run/7z2john.pl, scoped for the jtr-wasm build.
 *
 * Emits the "$7z$..." hash that John the Ripper's sevenzip format cracks.
 * Reuses the in-tree LZMA decoder (lzma/LzmaDec.c) for LZMA-encoded headers.
 *
 * v1 scope (covers the vast majority of password-protected .7z):
 *   - single AES coder + a single compressor (COPY/LZMA1/LZMA2/BZIP2/DEFLATE)
 *   - plain (0x01) or LZMA1-encoded (0x17) main header; no header encryption
 * Fails cleanly (message to stderr, non-zero, no hash) on:
 *   - preprocessor filters (BCJ/BCJ2/Delta), PPMD, multi-coder topologies,
 *     AES-encrypted headers, split volumes (.7z.NNN), SFX, truncated/corrupt.
 *
 * This file is wired into john's argv[0] dispatch as "7z2john" (see john.c).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "lzma/LzmaDec.h"

/* ----- 7z constants (from 7z2john.pl / 7zHeader.h) -------------------------- */
static const uint8_t SEVEN_ZIP_MAGIC[6] = {0x37,0x7a,0xbc,0xaf,0x27,0x1c};

enum {
    K_END = 0x00, K_HEADER = 0x01, K_ARCHIVE_PROPERTIES = 0x02,
    K_ADD_STREAMS_INFO = 0x03, K_MAIN_STREAMS_INFO = 0x04, K_FILES_INFO = 0x05,
    K_PACK_INFO = 0x06, K_UNPACK_INFO = 0x07, K_SUBSTREAMS_INFO = 0x08,
    K_SIZE = 0x09, K_CRC = 0x0a, K_FOLDER = 0x0b, K_CODERS_UNPACK_SIZE = 0x0c,
    K_NUM_UNPACK_STREAM = 0x0d, K_EMPTY_STREAM = 0x0e, K_EMPTY_FILE = 0x0f,
    K_ENCODED_HEADER = 0x17
};

/* codec ids (big-endian byte sequences as stored) */
static const uint8_t ID_AES[4]    = {0x06,0xf1,0x07,0x01};
static const uint8_t ID_LZMA1[3]  = {0x03,0x01,0x01};
static const uint8_t ID_LZMA2[1]  = {0x21};
static const uint8_t ID_BZIP2[3]  = {0x04,0x02,0x02};
static const uint8_t ID_DEFLATE[3]= {0x04,0x01,0x08};
static const uint8_t ID_COPY[1]   = {0x00};

#define MAX_CODERS   8
#define MAX_FOLDERS  64
#define MAX_PACK     256
#define DEFAULT_POWER 19

/* ----- bounded cursor over an in-memory buffer ----------------------------- */
typedef struct { const uint8_t *p; size_t len, pos; int err; } Rd;

static uint8_t rd_u8(Rd *r) {
    if (r->pos >= r->len) { r->err = 1; return 0; }
    return r->p[r->pos++];
}
static void rd_get(Rd *r, uint8_t *dst, size_t n) {
    if (r->pos + n > r->len) { r->err = 1; return; }
    if (dst) memcpy(dst, r->p + r->pos, n);
    r->pos += n;
}
static void rd_skip(Rd *r, size_t n) {
    if (r->pos + n > r->len) { r->err = 1; return; }
    r->pos += n;
}
static uint32_t rd_u32le(Rd *r) {
    uint8_t b[4]; rd_get(r, b, 4);
    return (uint32_t)b[0] | ((uint32_t)b[1]<<8) | ((uint32_t)b[2]<<16) | ((uint32_t)b[3]<<24);
}
static uint64_t rd_u64le(Rd *r) {
    uint8_t b[8]; rd_get(r, b, 8);
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (8*i);
    return v;
}
/* 7z variable-length number (read_number in the perl) */
static uint64_t rd_num(Rd *r) {
    uint8_t first = rd_u8(r);
    if ((first & 0x80) == 0) return first;
    uint64_t value = rd_u8(r);
    for (int i = 1; i < 8; i++) {
        uint8_t mask = (uint8_t)(0x80 >> i);
        if ((first & mask) == 0) {
            value |= ((uint64_t)(first & (mask - 1))) << (8*i);
            return value;
        }
        value |= ((uint64_t)rd_u8(r)) << (8*i);
    }
    return value;
}

/* boolean vectors (for digest "defined" flags) */
static void rd_bool_vector(Rd *r, int n, uint8_t *out) {
    uint8_t v = 0, mask = 0;
    for (int i = 0; i < n; i++) {
        if (mask == 0) { v = rd_u8(r); mask = 0x80; }
        out[i] = (v & mask) != 0;
        mask >>= 1;
    }
}
static void rd_bool_vector_all(Rd *r, int n, uint8_t *out) {
    uint8_t all_defined = rd_u8(r);
    if (all_defined) { for (int i = 0; i < n; i++) out[i] = 1; }
    else rd_bool_vector(r, n, out);
}

/* ----- parsed structures --------------------------------------------------- */
typedef struct {
    uint8_t  id[16]; int id_len;
    int      num_in, num_out;
    uint8_t  attr[512]; int attr_len;
} Coder;

typedef struct {
    int      num_coders;
    Coder    coders[MAX_CODERS];
    int      tot_in, tot_out;
    int      num_bindpairs;
    int      bind_in[MAX_CODERS], bind_out[MAX_CODERS]; /* in/out stream indices */
    int      num_packed;            /* input streams not bound = packed streams */
    uint64_t out_size[MAX_CODERS];  /* unpack size per coder output (1 out/coder) */
    uint64_t final_unpack;          /* folder output (the unbound out stream) */
    int      has_crc; uint32_t crc;
} Folder;

typedef struct {
    /* pack info */
    uint64_t pack_pos;
    int      num_pack;
    uint64_t pack_size[MAX_PACK];
    /* unpack info (folders) */
    int      num_folders;
    Folder   folders[MAX_FOLDERS];
    /* substreams: first substream crc + size (what the cracker needs) */
    int      sub_has_crc; uint32_t sub_crc;
    uint64_t sub_first_size;
} Streams;

/* ----- error helper -------------------------------------------------------- */
static int fail(const char *msg) { fprintf(stderr, "7z2john: %s\n", msg); return 0; }

/* ----- folder parse (read_seven_zip_folders) ------------------------------- */
static int parse_folder(Rd *r, Folder *f) {
    memset(f, 0, sizeof(*f));
    f->num_coders = (int)rd_num(r);
    if (r->err || f->num_coders < 1 || f->num_coders > MAX_CODERS)
        return fail("unsupported folder (coder count)");
    for (int c = 0; c < f->num_coders; c++) {
        Coder *cd = &f->coders[c];
        uint8_t main_byte = rd_u8(r);
        cd->id_len = main_byte & 0x0f;
        if (cd->id_len < 1 || cd->id_len > 15) return fail("bad coder id size");
        rd_get(r, cd->id, cd->id_len);
        if (main_byte & 0x10) {                 /* complex coder */
            cd->num_in  = (int)rd_num(r);
            cd->num_out = (int)rd_num(r);
        } else { cd->num_in = 1; cd->num_out = 1; }
        if (main_byte & 0x20) {                 /* has attributes */
            cd->attr_len = (int)rd_num(r);
            if (cd->attr_len < 0 || cd->attr_len > (int)sizeof(cd->attr))
                return fail("coder attr too large");
            rd_get(r, cd->attr, cd->attr_len);
        }
        if (main_byte & 0x80) return fail("unsupported coder (alt methods)");
        f->tot_in  += cd->num_in;
        f->tot_out += cd->num_out;
    }
    f->num_bindpairs = f->tot_out - 1;
    if (f->num_bindpairs < 0 || f->num_bindpairs >= MAX_CODERS)
        return fail("unsupported folder (bindpairs)");
    /* bindpairs: in_index, out_index pairs */
    uint8_t out_bound[MAX_CODERS]; memset(out_bound, 0, sizeof(out_bound));
    for (int b = 0; b < f->num_bindpairs; b++) {
        f->bind_in[b]  = (int)rd_num(r);
        f->bind_out[b] = (int)rd_num(r);
        if (f->bind_out[b] >= 0 && f->bind_out[b] < MAX_CODERS)
            out_bound[f->bind_out[b]] = 1;
    }
    f->num_packed = f->tot_in - f->num_bindpairs;
    if (f->num_packed != 1) {
        /* >1 packed stream means BCJ2-style topology — out of scope */
        return fail("unsupported folder (multiple packed streams)");
    }
    /* with 1 packed stream, the perl skips the explicit packed-index list */
    /* remember which output stream is the folder's final output (unbound) */
    f->final_unpack = 0;
    for (int o = 0; o < f->tot_out && o < MAX_CODERS; o++)
        if (!out_bound[o]) { /* mark by index; sizes filled later */ f->bind_in[MAX_CODERS-1] = o; break; }
    return r->err ? fail("truncated folder") : 1;
}

/* find coder index by codec id */
static int find_coder(const Folder *f, const uint8_t *id, int idlen) {
    for (int c = 0; c < f->num_coders; c++)
        if (f->coders[c].id_len == idlen && memcmp(f->coders[c].id, id, idlen) == 0)
            return c;
    return -1;
}

/* ----- streams_info parse (read_seven_zip_streams_info) --------------------- */
static int parse_streams_info(Rd *r, Streams *s) {
    memset(s, 0, sizeof(*s));
    s->sub_first_size = 0;
    uint64_t id = rd_num(r);

    if (id == K_PACK_INFO) {
        s->pack_pos = rd_num(r);
        s->num_pack = (int)rd_num(r);
        if (s->num_pack < 0 || s->num_pack > MAX_PACK) return fail("too many pack streams");
        uint64_t t = rd_num(r);
        if (t == K_SIZE) {
            for (int i = 0; i < s->num_pack; i++) s->pack_size[i] = rd_num(r);
            t = rd_num(r);
        }
        while (t == K_CRC) {                 /* optional pack CRCs — skip */
            uint8_t defined[MAX_PACK];
            rd_bool_vector_all(r, s->num_pack, defined);
            for (int i = 0; i < s->num_pack; i++) if (defined[i]) rd_skip(r, 4);
            t = rd_num(r);
        }
        if (t != K_END) return fail("pack_info: expected END");
        id = rd_num(r);
    }

    if (id == K_UNPACK_INFO) {
        uint64_t t = rd_num(r);
        if (t != K_FOLDER) return fail("unpack_info: expected FOLDER");
        s->num_folders = (int)rd_num(r);
        if (s->num_folders < 1 || s->num_folders > MAX_FOLDERS)
            return fail("unsupported folder count");
        uint8_t external = rd_u8(r);
        if (external) return fail("external folder data unsupported");
        for (int i = 0; i < s->num_folders; i++)
            if (!parse_folder(r, &s->folders[i])) return 0;
        /* coders unpack sizes */
        t = rd_num(r);
        if (t != K_CODERS_UNPACK_SIZE) return fail("expected CODERS_UNPACK_SIZE");
        for (int i = 0; i < s->num_folders; i++) {
            Folder *f = &s->folders[i];
            for (int o = 0; o < f->tot_out && o < MAX_CODERS; o++)
                f->out_size[o] = rd_num(r);
            int final_idx = f->bind_in[MAX_CODERS-1];
            if (final_idx >= 0 && final_idx < MAX_CODERS)
                f->final_unpack = f->out_size[final_idx];
        }
        /* optional folder CRCs */
        t = rd_num(r);
        if (t == K_CRC) {
            uint8_t defined[MAX_FOLDERS];
            rd_bool_vector_all(r, s->num_folders, defined);
            for (int i = 0; i < s->num_folders; i++) {
                if (defined[i]) {
                    Rd tmp = *r; (void)tmp;
                    uint32_t crc = rd_u32le(r);
                    s->folders[i].has_crc = 1; s->folders[i].crc = crc;
                }
            }
            t = rd_num(r);
        }
        if (t != K_END) return fail("unpack_info: expected END");
        id = rd_num(r);
    }

    if (id == K_SUBSTREAMS_INFO) {
        /* We only need the first substream's CRC + size. Default: 1 per folder. */
        int num_unpack[MAX_FOLDERS];
        for (int i = 0; i < s->num_folders; i++) num_unpack[i] = 1;
        uint64_t t = rd_num(r);
        if (t == K_NUM_UNPACK_STREAM) {
            for (int i = 0; i < s->num_folders; i++) num_unpack[i] = (int)rd_num(r);
            t = rd_num(r);
        }
        /* sizes: for folders with >1 substream, (n-1) explicit sizes; the rest implied */
        int total_substreams = 0, num_digests = 0;
        for (int i = 0; i < s->num_folders; i++) {
            total_substreams += num_unpack[i];
            if (!(num_unpack[i] == 1 && s->folders[i].has_crc)) num_digests += num_unpack[i];
        }
        /* first folder's first substream size default = folder final unpack
           (true when folder 0 has a single substream; overridden below if not) */
        s->sub_first_size = s->num_folders ? s->folders[0].final_unpack : 0;
        if (t == K_SIZE) {
            /* per 7z: for folders with >1 substream, (n-1) explicit sizes are
               stored; the last is implied. Read past them, capturing folder 0's
               first substream size. */
            for (int i = 0; i < s->num_folders; i++) {
                for (int j = 1; j < num_unpack[i]; j++) {
                    uint64_t sz = rd_num(r);
                    if (i == 0 && j == 1) s->sub_first_size = sz;
                }
            }
            t = rd_num(r);
        }
        if (t == K_CRC) {
            uint8_t *defined = (uint8_t *)calloc(total_substreams ? total_substreams : 1, 1);
            int dn = num_digests;
            uint8_t adef[256];
            if (dn > (int)sizeof(adef)) dn = (int)sizeof(adef);
            rd_bool_vector_all(r, dn, adef);
            for (int i = 0; i < dn; i++) {
                if (adef[i]) {
                    uint32_t crc = rd_u32le(r);
                    if (i == 0) { s->sub_has_crc = 1; s->sub_crc = crc; }
                }
            }
            free(defined);
            t = rd_num(r);
        }
        while (t != K_END && !r->err) t = rd_num(r);  /* tolerate extra fields */
        id = rd_num(r);
    }
    return r->err ? fail("truncated streams_info") : 1;
}

/* g_Alloc for the in-tree LZMA decoder (mirrors 7z_common_plug.c) */
static void *SzAlloc(ISzAllocPtr p, size_t size) { (void)p; return malloc(size); }
static void  SzFree(ISzAllocPtr p, void *addr)   { (void)p; free(addr); }
static const ISzAlloc g_Alloc = { SzAlloc, SzFree };

/* decode an LZMA1-encoded header in-place; returns malloc'd buffer (caller frees) */
static uint8_t *decode_encoded_header(const uint8_t *file, size_t file_len,
                                      Streams *hs, size_t *out_len) {
    if (hs->num_folders != 1) { fail("encoded header: unsupported folders"); return NULL; }
    Folder *f = &hs->folders[0];
    int li = find_coder(f, ID_LZMA1, 3);
    if (li < 0) { fail("encoded header not LZMA1 (header encryption unsupported)"); return NULL; }
    Coder *cd = &f->coders[li];
    if (cd->attr_len < LZMA_PROPS_SIZE) { fail("encoded header: bad LZMA props"); return NULL; }
    size_t pack_off = 32 + hs->pack_pos;
    size_t pack_len = (size_t)hs->pack_size[0];
    if (pack_off + pack_len > file_len) { fail("encoded header: pack out of range"); return NULL; }
    SizeT dst_len = (SizeT)f->final_unpack;
    uint8_t *dst = (uint8_t *)malloc(dst_len ? dst_len : 1);
    SizeT src_len = (SizeT)pack_len;
    ELzmaStatus status;
    SRes res = LzmaDecode(dst, &dst_len, file + pack_off, &src_len,
                          cd->attr, LZMA_PROPS_SIZE, LZMA_FINISH_END, &status, &g_Alloc);
    if (res != SZ_OK) { free(dst); fail("encoded header: LZMA decode failed"); return NULL; }
    *out_len = dst_len;
    return dst;
}

/* ----- hex helper ---------------------------------------------------------- */
static void put_hex(const uint8_t *b, size_t n) {
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { putchar(h[b[i]>>4]); putchar(h[b[i]&0xf]); }
}

/* ----- the extractor ------------------------------------------------------- */
static int extract(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return fail("cannot open file");
    fseek(fp, 0, SEEK_END);
    long fsz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsz < 32) { fclose(fp); return fail("not a 7z file (too small)"); }
    uint8_t *file = (uint8_t *)malloc(fsz);
    if (!file) { fclose(fp); return fail("oom"); }
    if (fread(file, 1, fsz, fp) != (size_t)fsz) { free(file); fclose(fp); return fail("read error"); }
    fclose(fp);

    if (memcmp(file, SEVEN_ZIP_MAGIC, 6) != 0) { free(file); return fail("not a 7z file (bad magic; SFX/split unsupported)"); }

    Rd sig = { file, (size_t)fsz, 0, 0 };
    rd_skip(&sig, 12);                 /* magic(6)+ver(2)+startCRC(4) */
    uint64_t next_off  = rd_u64le(&sig);
    uint64_t next_size = rd_u64le(&sig);
    (void)rd_u32le(&sig);              /* next header CRC */
    if (32 + next_off + next_size > (uint64_t)fsz) { free(file); return fail("header out of range"); }

    /* Read the next header; decode if encoded. */
    Rd hdr = { file + 32 + next_off, (size_t)next_size, 0, 0 };
    uint8_t *decoded = NULL; size_t decoded_len = 0;
    uint64_t id = rd_num(&hdr);
    if (id == K_ENCODED_HEADER) {
        Streams hs;
        if (!parse_streams_info(&hdr, &hs)) { free(file); return 0; }
        decoded = decode_encoded_header(file, fsz, &hs, &decoded_len);
        if (!decoded) { free(file); return 0; }
        hdr.p = decoded; hdr.len = decoded_len; hdr.pos = 0; hdr.err = 0;
        id = rd_num(&hdr);
    }
    if (id != K_HEADER) { free(decoded); free(file); return fail("missing 7z header"); }

    /* header -> (skip archive props/additional) -> main streams info */
    id = rd_num(&hdr);
    if (id == K_ARCHIVE_PROPERTIES) { free(decoded); free(file); return fail("archive properties unsupported"); }
    if (id == K_ADD_STREAMS_INFO)   { free(decoded); free(file); return fail("additional streams unsupported"); }
    if (id != K_MAIN_STREAMS_INFO)  { free(decoded); free(file); return fail("no main streams info (empty/non-encrypted?)"); }

    Streams s;
    if (!parse_streams_info(&hdr, &s)) { free(decoded); free(file); return 0; }

    /* Find a folder with an AES coder. */
    int fi = -1, aes_idx = -1;
    for (int i = 0; i < s.num_folders; i++) {
        int a = find_coder(&s.folders[i], ID_AES, 4);
        if (a >= 0) { fi = i; aes_idx = a; break; }
    }
    if (fi < 0) { free(decoded); free(file); return fail("no AES data found (archive not encrypted?)"); }
    Folder *f = &s.folders[fi];

    /* Topology: AES + (optional) one supported compressor. Refuse filters/exotic. */
    int type = 0, comp_idx = -1;
    const uint8_t *dprops = NULL; int dprops_len = 0;
    if (f->num_coders == 1) {
        type = 0;                                   /* stored/uncompressed */
    } else if (f->num_coders == 2) {
        comp_idx = (aes_idx == 0) ? 1 : 0;
        Coder *cc = &f->coders[comp_idx];
        if      (cc->id_len==3 && !memcmp(cc->id,ID_LZMA1,3))   { type=1; dprops=cc->attr; dprops_len=cc->attr_len; }
        else if (cc->id_len==1 && !memcmp(cc->id,ID_LZMA2,1))   { type=2; dprops=cc->attr; dprops_len=cc->attr_len; }
        else if (cc->id_len==3 && !memcmp(cc->id,ID_BZIP2,3))   { type=6; }
        else if (cc->id_len==3 && !memcmp(cc->id,ID_DEFLATE,3)) { type=7; }
        else if (cc->id_len==1 && !memcmp(cc->id,ID_COPY,1))    { type=0; }
        else { free(decoded); free(file); return fail("unsupported 7z method/filter (BCJ/Delta/PPMD not supported in v1)"); }
    } else {
        free(decoded); free(file);
        return fail("unsupported 7z method/filter (multi-coder/filter not supported in v1)");
    }

    /* AES properties: power, salt, iv (get_decoder_properties) */
    Coder *ac = &f->coders[aes_idx];
    int power = DEFAULT_POWER, salt_len = 0, iv_len = 16;
    uint8_t salt[32] = {0}, iv[16] = {0};
    if (ac->attr_len >= 1) {
        uint8_t b0 = ac->attr[0];
        power = b0 & 0x3f;
        if ((b0 & 0xc0) != 0) {
            salt_len = (b0 >> 7) & 1;
            iv_len   = (b0 >> 6) & 1;
            if (ac->attr_len >= 2) {
                uint8_t b1 = ac->attr[1];
                salt_len += (b1 >> 4);
                iv_len   += (b1 & 0x0f);
                int off = 2;
                if (salt_len > (int)sizeof(salt)) salt_len = (int)sizeof(salt);
                if (off + salt_len <= ac->attr_len) memcpy(salt, ac->attr + off, salt_len);
                off += salt_len;
                int ivc = iv_len > 16 ? 16 : iv_len;
                if (off + ivc <= ac->attr_len) memcpy(iv, ac->attr + off, ivc);
            }
        } else { iv_len = 16; }
    }

    /* Sizes (verified vs a real archive):
       data_len   = encrypted pack bytes               = pack_size[folder]
       packed_sz  = AES output (compressed stream len)  = out_size[aes_idx]
       crc_len    = decompressed size (folder output)   = final_unpack            */
    uint64_t data_len  = 0;
    /* pack stream for this folder: with 1 packed stream/folder, folder i uses
       pack index = sum of packed counts of previous folders (==i here). */
    int pack_index = fi;
    if (pack_index >= s.num_pack) { free(decoded); free(file); return fail("pack index out of range"); }
    data_len = s.pack_size[pack_index];
    uint64_t packed_sz = f->out_size[aes_idx];
    /* crc_len = size the cracker decompresses + CRC-checks. For a solid
       multi-file folder that's the FIRST substream (first file), not the whole
       folder output; for a single-file folder the two are equal. */
    uint64_t crc_len   = s.sub_first_size ? s.sub_first_size : f->final_unpack;

    uint32_t crc = s.sub_has_crc ? s.sub_crc : (f->has_crc ? f->crc : 0);

    /* data offset on disk */
    uint64_t data_off = 32 + s.pack_pos;
    for (int i = 0; i < pack_index; i++) data_off += s.pack_size[i];
    if (data_off + data_len > (uint64_t)fsz) { free(decoded); free(file); return fail("data out of range"); }
    if (data_len > 0x40000000ULL) { free(decoded); free(file); return fail("encrypted data too large"); }

    /* ---- emit:  basename:$7z$type$power$saltlen$salt$ivlen$iv$crc$datalen$packsz$data[$crclen$props] */
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    printf("%s:$7z$%d$%d$%d$", base, type, power, salt_len);
    put_hex(salt, salt_len);
    printf("$%d$", iv_len);
    put_hex(iv, 16);                                  /* iv always emitted padded to 16 */
    printf("$%u$%llu$%llu$", crc, (unsigned long long)data_len, (unsigned long long)packed_sz);
    put_hex(file + data_off, (size_t)data_len);
    if (type != 0 && type != 128) {
        printf("$%llu$", (unsigned long long)crc_len);
        if ((type & 0xf) != 6 && (type & 0xf) != 7 && dprops && dprops_len > 0)
            put_hex(dprops, (size_t)dprops_len);
    }
    putchar('\n');

    free(decoded); free(file);
    return 1;
}

int sevenzip2john(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: 7z2john <.7z file> [...]\n");
        return 1;
    }
    int ok_any = 0;
    for (int i = 1; i < argc; i++)
        if (extract(argv[i])) ok_any = 1;
    return ok_any ? 0 : 1;
}
