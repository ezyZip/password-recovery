/*
 * office2john.c — C port of run/office2john.py (olefile-based), for the jtr-wasm
 * build which cannot run Python. Emits "$office$*..." (2007/2010/2013 agile) and
 * "$oldoffice$..." (97-2003 RC4) hashes that John the Ripper cracks. Pure
 * parsing; all crypto happens later in office_fmt_plug.c / oldoffice_fmt_plug.c.
 *
 * Encrypted .doc/.xls/.ppt and modern .docx/.xlsx/.pptx are all OLE2/CFB files,
 * read via the bundled ole2.c reader. Output is parity-checked (normalized hash
 * field) against office2john.py; the cosmetic ":::summary:::" suffix that the
 * python appends for some legacy DOCs is intentionally omitted (loader metadata
 * the cracker ignores).
 *
 * Untrusted, browser-facing input: no assert()/abort(); every read is
 * bounds-checked (Rd cursor) and unsupported/corrupt inputs fail gracefully.
 *
 * Build into john: JOHN_OBJS + argv[0] dispatch (john.c).
 * Native parity harness: cc -DOFFICE2JOHN_STANDALONE -o office2john \
 *                            office2john.c ole2.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ole2.h"

/* ----- helpers ------------------------------------------------------------ */

static int off_fail(const char *path, const char *msg)
{
	fprintf(stderr, "office2john: %s: %s\n", path ? path : "?", msg);
	return 0;
}

static void put_hex(const unsigned char *s, size_t n)
{
	static const char hx[] = "0123456789abcdef";
	size_t i;
	for (i = 0; i < n; i++) { putchar(hx[s[i] >> 4]); putchar(hx[s[i] & 15]); }
}

static const char *base_name(const char *p)
{
	const char *b = strrchr(p, '/');
	return b ? b + 1 : p;
}

/* local memmem (avoid _GNU_SOURCE dependency) */
static const unsigned char *find_bytes(const unsigned char *hay, size_t hlen,
                                       const char *needle, size_t nlen)
{
	if (nlen == 0 || hlen < nlen) return NULL;
	for (size_t i = 0; i + nlen <= hlen; i++)
		if (hay[i] == (unsigned char)needle[0] && !memcmp(hay + i, needle, nlen))
			return hay + i;
	return NULL;
}

/* bounds-checked little-endian cursor */
typedef struct { const uint8_t *p; size_t len, pos; int err; } Rd;
static void rd_init(Rd *r, const uint8_t *p, size_t len) { r->p = p; r->len = len; r->pos = 0; r->err = 0; }
static uint16_t rd_u16(Rd *r)
{
	if (r->pos + 2 > r->len) { r->err = 1; return 0; }
	uint16_t v = (uint16_t)(r->p[r->pos] | (r->p[r->pos + 1] << 8)); r->pos += 2; return v;
}
static uint32_t rd_u32(Rd *r)
{
	if (r->pos + 4 > r->len) { r->err = 1; return 0; }
	uint32_t v = (uint32_t)r->p[r->pos] | ((uint32_t)r->p[r->pos + 1] << 8) |
	             ((uint32_t)r->p[r->pos + 2] << 16) | ((uint32_t)r->p[r->pos + 3] << 24);
	r->pos += 4; return v;
}
static const uint8_t *rd_ptr(Rd *r, size_t n)
{
	if (r->pos + n > r->len) { r->err = 1; return NULL; }
	const uint8_t *q = r->p + r->pos; r->pos += n; return q;
}
static void rd_skip(Rd *r, size_t n) { if (r->pos + n > r->len) r->err = 1; else r->pos += n; }
static void rd_seek(Rd *r, size_t off) { if (off > r->len) r->err = 1; else r->pos = off; }

/* RFC4648 base64 decode (whitespace tolerant). Returns out length, or -1. */
static int b64_decode(const char *in, size_t inlen, unsigned char *out, size_t cap)
{
	int8_t dec[256];
	for (int i = 0; i < 256; i++) dec[i] = -1;
	const char *A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	for (int i = 0; i < 64; i++) dec[(unsigned char)A[i]] = (int8_t)i;
	int val = 0, bits = 0; size_t o = 0;
	for (size_t i = 0; i < inlen; i++) {
		unsigned char c = (unsigned char)in[i];
		if (c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
		if (dec[c] < 0) return -1;
		val = (val << 6) | dec[c]; bits += 6;
		if (bits >= 8) { bits -= 8; if (o < cap) out[o++] = (unsigned char)((val >> bits) & 0xFF); }
	}
	return (int)o;
}

/* ----- $oldoffice$ emit --------------------------------------------------- */

static void emit_oldoffice(const char *base, int typ,
                           const unsigned char *salt, const unsigned char *verifier,
                           const unsigned char *vhash, int vhlen,
                           const unsigned char *second_block /* 32 bytes or NULL */)
{
	printf("%s:$oldoffice$%d*", base, typ);
	put_hex(salt, 16); putchar('*');
	put_hex(verifier, 16); putchar('*');
	put_hex(vhash, (size_t)vhlen);
	if (second_block) { putchar('*'); put_hex(second_block, 32); }
	putchar('\n');
}

/* ----- shared RC4 CryptoAPI EncryptionHeader+Verifier parser -------------- */
/* Cursor must be positioned at headerLength (caller has consumed the preceding
 * encryptionFlags). Mirrors office2john.py's "headerLength -= 4" cadence. */
typedef struct {
	uint32_t keySize, saltSize, vhSize;
	unsigned char salt[16], encVerifier[16], encVerifierHash[64];
} cryptoapi_t;

static int parse_cryptoapi(Rd *r, cryptoapi_t *c)
{
	uint32_t hl = rd_u32(r);
	rd_u32(r); rd_u32(r); rd_u32(r); rd_u32(r);   /* skipFlags, sizeExtra, algId, algHashId */
	c->keySize = rd_u32(r);
	rd_u32(r); rd_u32(r); rd_u32(r);              /* providerType, unused, unused */
	if (r->err || hl < 32 || hl > r->len) return 0;
	rd_skip(r, hl - 32);                          /* CSPName */
	c->saltSize = rd_u32(r);
	if (r->err || c->saltSize != 16) return 0;
	{ const uint8_t *s = rd_ptr(r, 16); if (!s) return 0; memcpy(c->salt, s, 16); }
	{ const uint8_t *v = rd_ptr(r, 16); if (!v) return 0; memcpy(c->encVerifier, v, 16); }
	c->vhSize = rd_u32(r);
	if (r->err || c->vhSize == 0 || c->vhSize > sizeof(c->encVerifierHash)) return 0;
	{ const uint8_t *h = rd_ptr(r, c->vhSize); if (!h) return 0; memcpy(c->encVerifierHash, h, c->vhSize); }
	return !r->err;
}

/* ----- legacy XLS (BIFF FILEPASS) ----------------------------------------- */

static int parse_xls(const char *base, const char *path,
                     const unsigned char *wb, size_t wblen)
{
	Rd r; rd_init(&r, wb, wblen);
	while (r.pos < wblen) {
		uint16_t type = rd_u16(&r);
		uint16_t length = rd_u16(&r);
		size_t data_pos = r.pos;
		const uint8_t *data = rd_ptr(&r, length);
		if (r.err || !data) break;
		if (type != 0x2F) continue;                    /* not FILEPASS */
		if (length == 4)
			return off_fail(path, "Excel 95 XOR obfuscation (unsupported)");
		if (length >= 2 && data[0] == 0 && data[1] == 0)
			return off_fail(path, "XOR obfuscation (unsupported)");
		if (length >= 54 && !memcmp(data, "\x01\x00\x01\x00\x01\x00", 6)) {
			/* RC4 basic: salt/verifier/verifierHash 16 bytes each after 6-byte hdr */
			emit_oldoffice(base, 0, data + 6, data + 22, data + 38, 16, NULL);
			return 1;
		}
		if (length >= 4 && data[0] == 1 && data[1] == 0 &&
		    (data[2] == 2 || data[2] == 3 || data[2] == 4) && data[3] == 0) {
			/* RC4 CryptoAPI: skip 2 + major(2)+minor(2)+flags(4) -> headerLength */
			Rd s; rd_init(&s, data, length);
			rd_skip(&s, 2); rd_u16(&s); rd_u16(&s); rd_u32(&s);
			cryptoapi_t c;
			if (!parse_cryptoapi(&s, &c)) return off_fail(path, "bad RC4 CryptoAPI header (xls)");
			if (c.vhSize != 20) return off_fail(path, "unexpected verifier hash size (xls)");
			int typ = (c.keySize == 40) ? 3 : 4;
			const unsigned char *sb = NULL;
			if (typ == 3 && data_pos + length <= wblen && wblen >= 1024 + 32)
				sb = wb + 1024;                         /* second block: Workbook[1024:1056] */
			emit_oldoffice(base, typ, c.salt, c.encVerifier, c.encVerifierHash, 20, sb);
			return 1;
		}
	}
	return off_fail(path, "cannot find RC4 pass info (xls) — encrypted?");
}

/* ----- legacy DOC --------------------------------------------------------- */

/* find_table: pick 0Table/1Table from the WordDocument FIB. Returns 0/1, or -1 */
static int find_table(const char *path, const unsigned char *wd, size_t wdlen)
{
	if (wdlen < 12 || wd[0] != 0xEC || wd[1] != 0xA5)
		return off_fail(path, "not a Word document (bad wIdent)") - 1;  /* -1 */
	uint8_t flags = wd[11];
	int F = flags & 1, G = (flags & 2) ? 1 : 0, M = (flags & 0x80) ? 1 : 0;
	if (F && M) { off_fail(path, "XOR obfuscation (unsupported, doc)"); return -1; }
	if (!F) { off_fail(path, "document is not encrypted (doc)"); return -1; }
	return G ? 1 : 0;
}

static int parse_doc(const char *base, const char *path,
                     const unsigned char *ts, size_t tslen)
{
	Rd r; rd_init(&r, ts, tslen);
	uint16_t major = rd_u16(&r);
	uint16_t minor = rd_u16(&r);
	if (r.err) return off_fail(path, "short table stream (doc)");
	if (major == 1 || minor == 1) {
		/* legacy RC4: salt/verifier/verifierHash 16 bytes each */
		const uint8_t *d = rd_ptr(&r, 48);
		if (!d) return off_fail(path, "short RC4 block (doc)");
		emit_oldoffice(base, 1, d, d + 16, d + 32, 16, NULL);
		return 1;
	}
	if (major >= 2 && minor == 2) {
		rd_u32(&r);                                    /* encryptionFlags */
		cryptoapi_t c;
		if (!parse_cryptoapi(&r, &c)) return off_fail(path, "bad RC4 CryptoAPI header (doc)");
		if (c.vhSize != 20) return off_fail(path, "unexpected verifier hash size (doc)");
		int typ = (c.keySize == 128) ? 4 : (c.keySize == 40) ? 3 : (c.keySize == 56) ? 5 : -1;
		if (typ < 0) return off_fail(path, "invalid keySize (doc)");
		const unsigned char *sb = NULL;
		if (typ == 3 && tslen >= 512 + 32) sb = ts + 512;  /* table[512:544] */
		emit_oldoffice(base, typ, c.salt, c.encVerifier, c.encVerifierHash, 20, sb);
		return 1;
	}
	return off_fail(path, "cannot find RC4 pass info (doc) — encrypted?");
}

/* ----- legacy PPT --------------------------------------------------------- */

static int ppt_emit_from(const char *base, const unsigned char *pptdoc, size_t pptlen,
                         Rd *r, int allow_second_block)
{
	rd_u32(r);                                         /* encryptionFlags */
	cryptoapi_t c;
	if (!parse_cryptoapi(r, &c)) return 0;
	if (c.vhSize != 20) return 0;
	int typ = (c.keySize == 128) ? 4 : (c.keySize == 40) ? 3 : (c.keySize == 0) ? 3 : -1;
	if (typ < 0) return 0;
	const unsigned char *sb = NULL;
	if (typ == 3 && allow_second_block && pptlen >= 32) sb = pptdoc;  /* pptdoc[0:32] */
	emit_oldoffice(base, typ, c.salt, c.encVerifier, c.encVerifierHash, 20, sb);
	return 1;
}

/* brute-force fallback: scan the whole file for an RC4 CryptoAPI signature */
static int parse_ppt_bf(const char *base, const char *path,
                        const unsigned char *file, size_t flen)
{
	for (size_t i = 0; i + 128 <= flen; i++) {
		Rd r; rd_init(&r, file + i, flen - i > 384 ? 384 : flen - i);
		uint16_t major = rd_u16(&r), minor = rd_u16(&r);
		if (major < 2 || minor != 2) continue;
		rd_u32(&r);                                    /* encryptionFlags */
		uint32_t hl = rd_u32(&r);
		rd_u32(&r);                                    /* skipFlags */
		uint32_t sizeExtra = rd_u32(&r);
		uint32_t algId = rd_u32(&r);
		uint32_t algHashId = rd_u32(&r);
		if (r.err || sizeExtra != 0 || algId != 0x6801 || algHashId != 0x8004) continue;
		uint32_t keySize = rd_u32(&r);
		rd_u32(&r); rd_u32(&r); rd_u32(&r);            /* providerType, unused, unused */
		if (r.err || hl < 32) continue;
		rd_skip(&r, hl - 32);
		uint32_t saltSize = rd_u32(&r);
		if (r.err || saltSize != 16) continue;
		const uint8_t *salt = rd_ptr(&r, 16);
		const uint8_t *verifier = rd_ptr(&r, 16);
		uint32_t vhSize = rd_u32(&r);
		if (!salt || !verifier || vhSize != 20) continue;
		const uint8_t *vhash = rd_ptr(&r, 20);
		if (!vhash) continue;
		int typ = (keySize == 128) ? 4 : 3;           /* 40 or 0 -> 3 */
		emit_oldoffice(base, typ, salt, verifier, vhash, 20, NULL);
		return 1;
	}
	return off_fail(path, "cannot find RC4 pass info (ppt) — encrypted?");
}

static int parse_ppt(const char *base, const char *path,
                     const unsigned char *file, size_t flen,
                     const unsigned char *curuser, size_t culen,
                     const unsigned char *pptdoc, size_t pptlen)
{
	/* find_ppt_type(Current User) -> offsetToCurrentEdit */
	Rd cu; rd_init(&cu, curuser, culen);
	rd_skip(&cu, 2); rd_u16(&cu); rd_u32(&cu);         /* hdr: unused, recType, recLen */
	rd_u32(&cu); rd_u32(&cu);                          /* size, headerToken */
	uint32_t offsetCur = rd_u32(&cu);
	if (cu.err) return parse_ppt_bf(base, path, file, flen);

	Rd r; rd_init(&r, pptdoc, pptlen);
	rd_seek(&r, offsetCur);
	rd_skip(&r, 2); uint16_t recType = rd_u16(&r); uint32_t recLen = rd_u32(&r);
	if (r.err || recLen != 32 || recType != 0x0FF5)
		return parse_ppt_bf(base, path, file, flen);
	rd_u32(&r);                                        /* lastSlideRef */
	rd_u16(&r); rd_skip(&r, 2);                        /* version, minor+major */
	rd_u32(&r);                                        /* offsetLastEdit */
	uint32_t offPersistDir = rd_u32(&r);
	rd_u32(&r); rd_u32(&r);                            /* docPersistIdRef, persistIdSeed */
	rd_u16(&r); rd_u16(&r);                            /* lastView, unused */
	uint16_t encSessionRef = rd_u16(&r);
	if (r.err) return parse_ppt_bf(base, path, file, flen);

	rd_seek(&r, offPersistDir);
	rd_skip(&r, 2); rd_u16(&r); rd_u32(&r); rd_skip(&r, 4);
	uint32_t persistOffset = 0;
	for (int i = 0; i < encSessionRef; i++) {
		persistOffset = rd_u32(&r);
		if (r.err) return parse_ppt_bf(base, path, file, flen);
	}
	rd_seek(&r, persistOffset);
	rd_skip(&r, 2); rd_u16(&r); rd_u32(&r);
	uint16_t major = rd_u16(&r), minor = rd_u16(&r);
	if (!r.err && major >= 2 && minor == 2 && ppt_emit_from(base, pptdoc, pptlen, &r, 1))
		return 1;
	return parse_ppt_bf(base, path, file, flen);
}

/* ----- modern agile (2010/2013) XML --------------------------------------- */

/* copy attribute value name="..." found within [tag,tag+taglen) into out */
static int xml_attr(const unsigned char *tag, size_t taglen, const char *name,
                    char *out, size_t cap)
{
	size_t nlen = strlen(name);
	const unsigned char *p = find_bytes(tag, taglen, name, nlen);
	while (p) {
		const unsigned char *q = p + nlen;
		size_t rem = taglen - (q - tag);
		/* require name then optional ws then '=' then optional ws then '"' */
		size_t i = 0;
		while (i < rem && (q[i] == ' ' || q[i] == '\t')) i++;
		if (i < rem && q[i] == '=') {
			i++;
			while (i < rem && (q[i] == ' ' || q[i] == '\t')) i++;
			if (i < rem && q[i] == '"') {
				i++; size_t o = 0;
				while (i < rem && q[i] != '"') { if (o + 1 < cap) out[o++] = (char)q[i]; i++; }
				out[o] = '\0';
				return (int)o;
			}
		}
		p = find_bytes(q, taglen - (q - tag), name, nlen);  /* try next occurrence */
	}
	return -1;
}

static int parse_agile_xml(const char *base, const char *path,
                           const unsigned char *xml, size_t xmllen)
{
	const unsigned char *ek = find_bytes(xml, xmllen, "encryptedKey", 12);
	if (!ek) return off_fail(path, "no encryptedKey element (agile)");
	/* bound the <...encryptedKey ...> start tag */
	const unsigned char *ts = ek; while (ts > xml && *ts != '<') ts--;
	const unsigned char *te = ek; while (te < xml + xmllen && *te != '>') te++;
	size_t taglen = (size_t)(te - ts);

	char spin[32], saltSz[32], keyBits[32], hashAlg[64], cipher[64];
	char saltV[512], vhi[512], vhv[512];
	if (xml_attr(ts, taglen, "spinCount", spin, sizeof(spin)) < 0 ||
	    xml_attr(ts, taglen, "saltSize", saltSz, sizeof(saltSz)) < 0 ||
	    xml_attr(ts, taglen, "keyBits", keyBits, sizeof(keyBits)) < 0 ||
	    xml_attr(ts, taglen, "hashAlgorithm", hashAlg, sizeof(hashAlg)) < 0 ||
	    xml_attr(ts, taglen, "cipherAlgorithm", cipher, sizeof(cipher)) < 0 ||
	    xml_attr(ts, taglen, "saltValue", saltV, sizeof(saltV)) < 0 ||
	    xml_attr(ts, taglen, "encryptedVerifierHashInput", vhi, sizeof(vhi)) < 0 ||
	    xml_attr(ts, taglen, "encryptedVerifierHashValue", vhv, sizeof(vhv)) < 0)
		return off_fail(path, "missing agile encryptedKey attributes");

	int version;
	if (!strcmp(hashAlg, "SHA1")) version = 2010;
	else if (!strcmp(hashAlg, "SHA512")) version = 2013;
	else return off_fail(path, "unsupported hashing algorithm (agile)");
	if (!strstr(cipher, "AES")) return off_fail(path, "unsupported cipher algorithm (agile)");

	unsigned char salt[256], dvhi[256], dvhv[256];
	int sl = b64_decode(saltV, strlen(saltV), salt, sizeof(salt));
	int il = b64_decode(vhi, strlen(vhi), dvhi, sizeof(dvhi));
	int vl = b64_decode(vhv, strlen(vhv), dvhv, sizeof(dvhv));
	if (sl <= 0 || il <= 0 || vl <= 0) return off_fail(path, "base64 decode failed (agile)");

	printf("%s:$office$*%d*%d*%d*%d*", base, version, atoi(spin), atoi(keyBits), atoi(saltSz));
	put_hex(salt, (size_t)sl); putchar('*');
	put_hex(dvhi, (size_t)il); putchar('*');
	put_hex(dvhv, (size_t)(vl < 32 ? vl : 32));        /* truncate to 64 hex */
	putchar('\n');
	return 1;
}

/* ----- modern EncryptionInfo (2007 standard or agile) --------------------- */

static int process_new_office(const char *base, const char *path, ole_file *ole)
{
	const ole_entry *e = ole_find_stream(ole, "EncryptionInfo");
	size_t n; unsigned char *ei = ole_read_stream(ole, e, &n);
	if (!ei) return off_fail(path, "cannot read EncryptionInfo");
	Rd r; rd_init(&r, ei, n);
	uint16_t major = rd_u16(&r), minor = rd_u16(&r);
	uint32_t flags = rd_u32(&r);
	int ret;
	if (flags == 16) { free(ei); return off_fail(path, "external cryptographic provider (unsupported)"); }
	if (major == 4 && minor == 4) {                    /* agile 2010/2013 */
		if (flags != 0x40) { free(ei); return off_fail(path, "inconsistent agile flags"); }
		ret = parse_agile_xml(base, path, ei + r.pos, n - r.pos);
	} else {                                            /* 2007 standard */
		cryptoapi_t c;
		if (!parse_cryptoapi(&r, &c)) { free(ei); return off_fail(path, "bad 2007 EncryptionHeader"); }
		printf("%s:$office$*2007*%u*%u*%u*", base, c.vhSize, c.keySize, c.saltSize);
		put_hex(c.salt, 16); putchar('*');
		put_hex(c.encVerifier, 16); putchar('*');
		put_hex(c.encVerifierHash, c.vhSize < 32 ? c.vhSize : 32);
		putchar('\n');
		ret = 1;
	}
	free(ei);
	return ret;
}

/* ----- top-level dispatch ------------------------------------------------- */

static int read_named(ole_file *ole, const char *name, unsigned char **buf, size_t *len)
{
	const ole_entry *e = ole_find_stream(ole, name);
	if (!e) return 0;
	*buf = ole_read_stream(ole, e, len);
	return *buf != NULL;
}

static int process_file(const char *path)
{
	FILE *fp = fopen(path, "rb");
	if (!fp) return off_fail(path, "cannot open");
	fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
	if (sz <= 0) { fclose(fp); return off_fail(path, "empty file"); }
	unsigned char *file = malloc((size_t)sz);
	if (!file) { fclose(fp); return off_fail(path, "out of memory"); }
	if (fread(file, 1, (size_t)sz, fp) != (size_t)sz) { free(file); fclose(fp); return off_fail(path, "short read"); }
	fclose(fp);
	size_t flen = (size_t)sz;
	const char *base = base_name(path);
	size_t plen = flen < 81920 ? flen : 81920;        /* pre-check window */

	int rc = 0;

	if (flen >= 2 && file[0] == 'P' && file[1] == 'K') {
		off_fail(path, "zip container — unencrypted OOXML / invalid OLE");
		free(file); return 0;
	}
	/* ACCDB / OneNote agile-XML hacks */
	if (find_bytes(file, plen, "Standard ACE DB", 15)) {
		const unsigned char *xs = find_bytes(file, plen, "<?xml version=\"1.0\"", 19);
		const unsigned char *xt = find_bytes(file, plen, "</encryption>", 13);
		if (xs && xt && xt > xs) {
			rc = parse_agile_xml(base, path, xs, (size_t)(xt - xs) + 13);
		} else {
			off_fail(path, "Access CryptoAPI (.accdb, non-agile) not supported");
		}
		free(file); return rc;
	}
	{
		static const unsigned char onenote[6] = { 0xe4,0x52,0x5c,0x7b,0x8c,0xd8 };
		if (flen >= 6 && !memcmp(file, onenote, 6)) {
			const unsigned char *xs = find_bytes(file, plen, "<?xml version=\"1.0\"", 19);
			const unsigned char *xt = find_bytes(file, plen, "</encryption>", 13);
			if (xs && xt && xt > xs) rc = parse_agile_xml(base, path, xs, (size_t)(xt - xs) + 13);
			else off_fail(path, "OneNote (non-agile) not supported");
			free(file); return rc;
		}
	}

	ole_file *ole = ole_open(file, flen);
	if (!ole) { off_fail(path, "Invalid OLE file"); free(file); return 0; }

	unsigned char *s = NULL; size_t sl = 0;
	if (ole_find_stream(ole, "EncryptionInfo")) {
		rc = process_new_office(base, path, ole);
	} else if (read_named(ole, "Workbook", &s, &sl) || read_named(ole, "Book", &s, &sl)) {
		rc = parse_xls(base, path, s, sl);
	} else if (read_named(ole, "WordDocument", &s, &sl)) {
		int which = find_table(path, s, sl);
		if (which >= 0) {
			unsigned char *t = NULL; size_t tl = 0;
			if (read_named(ole, which ? "1Table" : "0Table", &t, &tl)) {
				rc = parse_doc(base, path, t, tl);
				free(t);
			} else off_fail(path, "table stream not found (doc)");
		}
	} else if (ole_find_stream(ole, "PowerPoint Document")) {
		unsigned char *cu = NULL, *pd = NULL; size_t cl = 0, pl = 0;
		if (read_named(ole, "Current User", &cu, &cl) &&
		    read_named(ole, "PowerPoint Document", &pd, &pl))
			rc = parse_ppt(base, path, file, flen, cu, cl, pd, pl);
		else off_fail(path, "PowerPoint streams not found");
		free(cu); free(pd);
	} else {
		off_fail(path, "no supported streams found");
	}

	free(s);
	ole_close(ole);
	free(file);
	return rc;
}

int office2john(int argc, char **argv)
{
	int i, ok = 0;
	if (argc < 2) { fprintf(stderr, "Usage: office2john <Office file> [...]\n"); return 1; }
	for (i = 1; i < argc; i++)
		if (process_file(argv[i])) ok = 1;
	return ok ? 0 : 1;
}

#if defined(OFFICE2JOHN_STANDALONE) && !defined(__EMSCRIPTEN__)
int main(int argc, char **argv) { return office2john(argc, argv); }
#endif
