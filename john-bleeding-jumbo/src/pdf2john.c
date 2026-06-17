/*
 * pdf2john.c — C port of run/pdf2john.py (pyhanko-based), scoped for the
 * jtr-wasm build which cannot run Python. Emits the "$pdf$..." hash that John
 * the Ripper's PDF format cracks. Pure parsing; no crypto at extraction time.
 *
 * Output (byte-identical to the current pdf2john.py, modulo a "name:" prefix):
 *   $pdf$<V>*<R>*<Length>*<P>*<EncMeta>*<id_len>*<id_hex>
 *        *<u_len>*<u_hex>*<o_len>*<o_hex>[*<oe_len>*<oe_hex>][*<ue_len>*<ue_hex>]
 *   /O,/U truncated to 32 bytes (R<5) or 48 bytes (R>=5); /OE,/UE for R5/R6.
 *
 * Strategy (no full xref parser): the /Encrypt dict is never encrypted and is
 * virtually always a direct, uncompressed object, so:
 *   primary  — find the LAST "/Encrypt N G R" reference (the active trailer /
 *              xref-stream dict) + LAST "/ID", resolve object N -> its dict.
 *   fallback — scan for "/Filter /Standard" and use its enclosing object dict.
 * Dictionary boundaries are found with a string/comment-aware tokenizer so a
 * '>' inside a value never closes the dict early.
 *
 * Unsupported / malformed inputs fail gracefully (stderr + skip); never abort.
 *
 * Build into john: linked via JOHN_OBJS, dispatched by argv[0] (john.c).
 * Native parity harness: cc -DPDF2JOHN_STANDALONE -o pdf2john pdf2john.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

/* ----- small byte helpers ------------------------------------------------- */

static int pdf_fail(const char *path, const char *msg)
{
	fprintf(stderr, "pdf2john: %s: %s\n", path ? path : "?", msg);
	return 0;
}

static void put_hex(const unsigned char *s, size_t n)
{
	static const char hx[] = "0123456789abcdef";
	size_t i;
	for (i = 0; i < n; i++) {
		putchar(hx[s[i] >> 4]);
		putchar(hx[s[i] & 15]);
	}
}

/* naive forward search; returns index of needle in hay[from..len) or -1 */
static long mem_find(const unsigned char *hay, size_t len, size_t from,
                     const char *needle, size_t nlen)
{
	if (nlen == 0 || len < nlen) return -1;
	for (size_t i = from; i + nlen <= len; i++)
		if (hay[i] == (unsigned char)needle[0] && !memcmp(hay + i, needle, nlen))
			return (long)i;
	return -1;
}

/* last occurrence of needle within hay[0..upto) */
static long mem_rfind(const unsigned char *hay, size_t upto,
                      const char *needle, size_t nlen)
{
	if (nlen == 0 || upto < nlen) return -1;
	for (long i = (long)(upto - nlen); i >= 0; i--)
		if (hay[i] == (unsigned char)needle[0] && !memcmp(hay + i, needle, nlen))
			return i;
	return -1;
}

static int is_ws(int c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == 0;
}
static int is_delim(int c)
{
	return c == '(' || c == ')' || c == '<' || c == '>' || c == '[' ||
	       c == ']' || c == '{' || c == '}' || c == '/' || c == '%';
}

/* skip whitespace and %-comments starting at i; returns new index */
static size_t skip_ws(const unsigned char *d, size_t n, size_t i)
{
	while (i < n) {
		if (is_ws(d[i])) { i++; continue; }
		if (d[i] == '%') {                 /* comment to end of line */
			while (i < n && d[i] != '\n' && d[i] != '\r') i++;
			continue;
		}
		break;
	}
	return i;
}

static size_t skip_name(const unsigned char *d, size_t n, size_t i)
{
	i++;                                   /* the leading '/' */
	while (i < n && !is_ws(d[i]) && !is_delim(d[i])) i++;
	return i;
}

static size_t skip_number(const unsigned char *d, size_t n, size_t i)
{
	if (i < n && (d[i] == '+' || d[i] == '-')) i++;
	while (i < n && (isdigit(d[i]) || d[i] == '.')) i++;
	return i;
}

static size_t skip_keyword(const unsigned char *d, size_t n, size_t i)
{
	while (i < n && !is_ws(d[i]) && !is_delim(d[i])) i++;
	return i;
}

static size_t skip_literal_string(const unsigned char *d, size_t n, size_t i)
{
	int depth = 0;
	/* i points at '(' */
	for (; i < n; i++) {
		if (d[i] == '\\') { i++; continue; }      /* escape: skip next */
		if (d[i] == '(') depth++;
		else if (d[i] == ')') { depth--; if (depth == 0) return i + 1; }
	}
	return n;
}

static size_t skip_hex_string(const unsigned char *d, size_t n, size_t i)
{
	/* i points at '<' (not '<<') */
	for (i++; i < n; i++)
		if (d[i] == '>') return i + 1;
	return n;
}

static size_t skip_token(const unsigned char *d, size_t n, size_t i);

static size_t skip_dict(const unsigned char *d, size_t n, size_t i)
{
	/* i points at "<<" */
	i += 2;
	while (i < n) {
		i = skip_ws(d, n, i);
		if (i + 1 < n && d[i] == '>' && d[i + 1] == '>') return i + 2;
		if (i >= n) break;
		i = skip_token(d, n, i);
	}
	return n;
}

static size_t skip_array(const unsigned char *d, size_t n, size_t i)
{
	i++;                                   /* '[' */
	while (i < n) {
		i = skip_ws(d, n, i);
		if (i < n && d[i] == ']') return i + 1;
		if (i >= n) break;
		i = skip_token(d, n, i);
	}
	return n;
}

/* skip a single value token starting at i (after ws); handles "N G R" refs */
static size_t skip_token(const unsigned char *d, size_t n, size_t i)
{
	unsigned char c = d[i];
	if (c == '(') return skip_literal_string(d, n, i);
	if (c == '<') {
		if (i + 1 < n && d[i + 1] == '<') return skip_dict(d, n, i);
		return skip_hex_string(d, n, i);
	}
	if (c == '[') return skip_array(d, n, i);
	if (c == '/') return skip_name(d, n, i);
	if (c == '+' || c == '-' || isdigit(c)) {
		size_t j = skip_number(d, n, i);
		size_t k = skip_ws(d, n, j);          /* possible "G R" indirect ref */
		if (k < n && isdigit(d[k])) {
			size_t m = skip_number(d, n, k);
			size_t p = skip_ws(d, n, m);
			if (p < n && d[p] == 'R' &&
			    (p + 1 >= n || is_ws(d[p + 1]) || is_delim(d[p + 1])))
				return p + 1;
		}
		return j;
	}
	return skip_keyword(d, n, i);             /* true/false/null/R/obj... */
}

/* Find a top-level key "/Name" within dict content [d, d+n); on success set
 * the value token span (vs..ve) and return 1. */
static int dict_lookup(const unsigned char *d, size_t n, const char *key,
                       size_t *vs, size_t *ve)
{
	size_t klen = strlen(key);
	size_t i = 0;
	while (i < n) {
		i = skip_ws(d, n, i);
		if (i >= n) break;
		if (d[i] == '/') {
			size_t name_start = i;
			size_t name_end = skip_name(d, n, i);
			size_t vstart = skip_ws(d, n, name_end);
			size_t vend = (vstart < n) ? skip_token(d, n, vstart) : vstart;
			if (name_end - name_start == klen &&
			    !memcmp(d + name_start, key, klen)) {
				*vs = vstart; *ve = vend;
				return 1;
			}
			i = vend;
		} else {
			i = skip_token(d, n, i);
		}
	}
	return 0;
}

/* Parse a PDF string value (literal "(...)" or hex "<...>") at [d+s, d+e) into
 * out (<=cap bytes). Returns byte length, or -1 on error. */
static int parse_pdf_string(const unsigned char *d, size_t s, size_t e,
                            unsigned char *out, size_t cap)
{
	size_t i = s, o = 0;
	if (i >= e) return -1;
	if (d[i] == '<') {                          /* hex string */
		int hi = -1;
		for (i++; i < e && d[i] != '>'; i++) {
			int c = d[i], v;
			if (is_ws(c)) continue;
			if (c >= '0' && c <= '9') v = c - '0';
			else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
			else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
			else return -1;
			if (hi < 0) hi = v;
			else { if (o < cap) out[o++] = (hi << 4) | v; hi = -1; }
		}
		if (hi >= 0 && o < cap) out[o++] = hi << 4; /* odd nibble padded */
		return (int)o;
	}
	if (d[i] != '(') return -1;                 /* literal string */
	int depth = 0;
	for (; i < e; i++) {
		int c = d[i];
		if (c == '\\') {
			i++;
			if (i >= e) break;
			c = d[i];
			switch (c) {
			case 'n': if (o < cap) out[o++] = '\n'; break;
			case 'r': if (o < cap) out[o++] = '\r'; break;
			case 't': if (o < cap) out[o++] = '\t'; break;
			case 'b': if (o < cap) out[o++] = '\b'; break;
			case 'f': if (o < cap) out[o++] = '\f'; break;
			case '(': case ')': case '\\':
				if (o < cap) out[o++] = c; break;
			case '\r': if (i + 1 < e && d[i + 1] == '\n') i++; break; /* line cont */
			case '\n': break;                  /* line continuation */
			default:
				if (c >= '0' && c <= '7') {     /* octal escape, 1-3 digits */
					int v = c - '0', k = 0;
					while (k < 2 && i + 1 < e && d[i + 1] >= '0' && d[i + 1] <= '7') {
						v = (v << 3) | (d[++i] - '0'); k++;
					}
					if (o < cap) out[o++] = (unsigned char)v;
				} else if (o < cap) out[o++] = c; /* unknown escape: literal */
			}
			continue;
		}
		if (c == '(') { depth++; if (o < cap) out[o++] = c; continue; }
		if (c == ')') {
			if (depth == 0) return (int)o;     /* end of string */
			depth--; if (o < cap) out[o++] = c; continue;
		}
		if (c == '\r') {                        /* EOL -> single 0x0A (spec) */
			if (i + 1 < e && d[i + 1] == '\n') i++;
			if (o < cap) out[o++] = '\n'; continue;
		}
		if (o < cap) out[o++] = c;
	}
	return (int)o;
}

/* ----- locate the Encrypt dict and the document /ID --------------------- */

/* find the definition of object `num`: returns offset just after "obj", or -1.
 * Tolerant of arbitrary whitespace; scans "obj" keywords and parses the two
 * preceding integers (N G). Returns the LAST matching definition. */
static long find_object(const unsigned char *f, size_t flen, long num)
{
	long best = -1, at = 0;
	for (;;) {
		long p = mem_find(f, flen, (size_t)at, "obj", 3);
		if (p < 0) break;
		at = p + 3;
		/* require word boundary before/after (avoid "endobj", "objstm") */
		if (p > 0 && !is_ws(f[p - 1]) && !is_delim(f[p - 1])) continue;
		if ((size_t)(p + 3) < flen && !is_ws(f[p + 3]) && !is_delim(f[p + 3])) continue;
		/* parse backwards: ws, G(int), ws, N(int) */
		long q = p - 1;
		while (q >= 0 && is_ws(f[q])) q--;
		long ge = q; while (q >= 0 && isdigit(f[q])) q--;
		if (q == ge) continue;                 /* no G */
		while (q >= 0 && is_ws(f[q])) q--;
		long ne = q; while (q >= 0 && isdigit(f[q])) q--;
		if (q == ne) continue;                 /* no N */
		if (q >= 0 && isdigit(f[q])) continue;  /* N must start at a boundary */
		long n = strtol((const char *)f + q + 1, NULL, 10);
		if (n == num) best = p + 3;             /* keep last */
	}
	return best;
}

/* Given an offset pointing into the file where an object's body begins (after
 * "obj"), return the dict content span [*ds,*de) (between "<<" and ">>"). */
static int dict_at(const unsigned char *f, size_t flen, size_t from,
                   size_t *ds, size_t *de)
{
	size_t i = skip_ws(f, flen, from);
	if (i + 1 >= flen || f[i] != '<' || f[i + 1] != '<') return 0;
	size_t end = skip_dict(f, flen, i);        /* end is just after ">>" */
	if (end <= i + 4) return 0;
	*ds = i + 2;
	*de = end - 2;
	return 1;
}

/* primary: last "/Encrypt N G R" (or inline "/Encrypt <<...>>"); resolve. */
static int find_encrypt_dict(const unsigned char *f, size_t flen,
                             size_t *ds, size_t *de)
{
	long at = 0, best_obj = -1;
	int best_inline_ok = 0; size_t bi_s = 0, bi_e = 0;
	for (;;) {
		long p = mem_find(f, flen, (size_t)at, "/Encrypt", 8);
		if (p < 0) break;
		at = p + 8;
		size_t i = skip_ws(f, flen, (size_t)p + 8);
		if (i + 1 < flen && f[i] == '<' && f[i + 1] == '<') {  /* inline dict */
			size_t end = skip_dict(f, flen, i);
			if (end > i + 4) { best_inline_ok = 1; bi_s = i + 2; bi_e = end - 2; best_obj = -1; }
			continue;
		}
		if (i < flen && isdigit(f[i])) {           /* indirect ref "N G R" */
			long num = strtol((const char *)f + i, NULL, 10);
			best_obj = num; best_inline_ok = 0;
		}
	}
	if (best_inline_ok) { *ds = bi_s; *de = bi_e; return 1; }
	if (best_obj >= 0) {
		long body = find_object(f, flen, best_obj);
		if (body >= 0 && dict_at(f, flen, (size_t)body, ds, de)) return 1;
	}
	/* fallback: object containing "/Filter /Standard" (or "/Filter/Standard") */
	long sp = -1;
	{
		long a = mem_rfind(f, flen, "/Standard", 9);
		if (a >= 0) sp = a;
	}
	if (sp >= 0) {
		long body = mem_rfind(f, (size_t)sp, "obj", 3);
		if (body >= 0 && dict_at(f, flen, (size_t)body + 3, ds, de)) return 1;
	}
	return 0;
}

/* document /ID first element -> raw bytes. Returns length (>=0), or -1 absent. */
static int find_document_id(const unsigned char *f, size_t flen,
                            unsigned char *out, size_t cap)
{
	long at = 0, idpos = -1;
	for (;;) {                                  /* take the LAST /ID */
		long p = mem_find(f, flen, (size_t)at, "/ID", 3);
		if (p < 0) break;
		at = p + 3;
		/* must be a delimiter/ws after "/ID" then '[' */
		size_t i = (size_t)p + 3;
		if (i < flen && !is_ws(f[i]) && f[i] != '[') continue;
		i = skip_ws(f, flen, i);
		if (i < flen && f[i] == '[') idpos = (long)i;
	}
	if (idpos < 0) return -1;
	size_t i = skip_ws(f, flen, (size_t)idpos + 1);
	if (i >= flen || (f[i] != '<' && f[i] != '(')) return -1;
	size_t vend = skip_token(f, flen, i);
	return parse_pdf_string(f, i, vend, out, cap);
}

/* ----- main extraction ---------------------------------------------------- */

static const char *base_name(const char *path)
{
	const char *b = strrchr(path, '/');
	return b ? b + 1 : path;
}

static int extract(const char *path)
{
	FILE *fp = fopen(path, "rb");
	if (!fp) return pdf_fail(path, "cannot open");
	fseek(fp, 0, SEEK_END);
	long sz = ftell(fp);
	if (sz <= 0) { fclose(fp); return pdf_fail(path, "empty file"); }
	fseek(fp, 0, SEEK_SET);
	unsigned char *f = malloc((size_t)sz);
	if (!f) { fclose(fp); return pdf_fail(path, "out of memory"); }
	if (fread(f, 1, (size_t)sz, fp) != (size_t)sz) { free(f); fclose(fp); return pdf_fail(path, "short read"); }
	fclose(fp);

	size_t ds, de;
	if (!find_encrypt_dict(f, (size_t)sz, &ds, &de)) {
		free(f);
		return pdf_fail(path, "no Standard /Encrypt dictionary found (unencrypted or unsupported)");
	}
	const unsigned char *D = f + ds;
	size_t DN = de - ds;

	size_t vs, ve;
	long V, R, length = 40;
	long P;
	int encmeta = 1;

	if (!dict_lookup(D, DN, "/V", &vs, &ve)) { free(f); return pdf_fail(path, "missing /V"); }
	V = strtol((const char *)D + vs, NULL, 10);
	if (!dict_lookup(D, DN, "/R", &vs, &ve)) { free(f); return pdf_fail(path, "missing /R"); }
	R = strtol((const char *)D + vs, NULL, 10);
	if (dict_lookup(D, DN, "/Length", &vs, &ve))
		length = strtol((const char *)D + vs, NULL, 10);
	if (!dict_lookup(D, DN, "/P", &vs, &ve)) { free(f); return pdf_fail(path, "missing /P"); }
	P = strtol((const char *)D + vs, NULL, 10);
	if (dict_lookup(D, DN, "/EncryptMetadata", &vs, &ve)) {
		if (ve - vs >= 5 && !memcmp(D + vs, "false", 5)) encmeta = 0;
	}

	unsigned char U[256], O[256], OE[256], UE[256];
	int ulen = -1, olen = -1, oelen = -1, uelen = -1;
	if (dict_lookup(D, DN, "/U", &vs, &ve)) ulen = parse_pdf_string(D, vs, ve, U, sizeof(U));
	if (dict_lookup(D, DN, "/O", &vs, &ve)) olen = parse_pdf_string(D, vs, ve, O, sizeof(O));
	if (dict_lookup(D, DN, "/UE", &vs, &ve)) uelen = parse_pdf_string(D, vs, ve, UE, sizeof(UE));
	if (dict_lookup(D, DN, "/OE", &vs, &ve)) oelen = parse_pdf_string(D, vs, ve, OE, sizeof(OE));

	if (ulen <= 0 || olen <= 0) { free(f); return pdf_fail(path, "missing or malformed /U or /O"); }

	/* truncate O/U/OE/UE to the revision key length (R>=5 -> 48 else 32) */
	int maxkl = (R >= 5) ? 48 : 32;
	if (ulen > maxkl) ulen = maxkl;
	if (olen > maxkl) olen = maxkl;
	if (oelen > maxkl) oelen = maxkl;
	if (uelen > maxkl) uelen = maxkl;

	unsigned char id[256];
	int idlen = find_document_id(f, (size_t)sz, id, sizeof(id));
	if (idlen < 0) idlen = 0;                   /* superset: cracker accepts id_len 0 */

	/* emit: name:$pdf$V*R*Length*P*EncMeta*idlen*idhex*ulen*u*olen*o[*oe][*ue] */
	printf("%s:$pdf$%ld*%ld*%ld*%ld*%d*%d*", base_name(path), V, R, length, P, encmeta, idlen);
	put_hex(id, (size_t)idlen);
	printf("*%d*", ulen); put_hex(U, (size_t)ulen);
	printf("*%d*", olen); put_hex(O, (size_t)olen);
	if (oelen > 0) { printf("*%d*", oelen); put_hex(OE, (size_t)oelen); }
	if (uelen > 0) { printf("*%d*", uelen); put_hex(UE, (size_t)uelen); }
	putchar('\n');

	free(f);
	return 1;
}

int pdf2john(int argc, char **argv)
{
	int i, ok = 0;
	if (argc < 2) {
		fprintf(stderr, "Usage: pdf2john <PDF file> [...]\n");
		return 1;
	}
	for (i = 1; i < argc; i++)
		if (extract(argv[i])) ok = 1;
	return ok ? 0 : 1;
}

#if defined(PDF2JOHN_STANDALONE) && !defined(__EMSCRIPTEN__)
int main(int argc, char **argv) { return pdf2john(argc, argv); }
#endif
