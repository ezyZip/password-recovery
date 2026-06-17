/*
 * ole2_contract_test.c — standalone harness for the CFB reader (src/ole2.c),
 * the highest-risk new code. Run modes:
 *
 *   ole2_contract_test <file>            -> prints "<name>\t<size>" per stream
 *   ole2_contract_test <file> <stream>   -> writes that stream's raw bytes to stdout
 *
 * The python driver (test/test-ole2-contract.py) diffs both the listing and the
 * per-stream bytes against python's `olefile`, including a mini-FAT (<4096B)
 * stream. Build: cc -I../john-bleeding-jumbo/src -o ole2_contract_test \
 *                   ole2_contract_test.c ../john-bleeding-jumbo/src/ole2.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ole2.h"

static unsigned char *slurp(const char *path, size_t *len)
{
	FILE *fp = fopen(path, "rb");
	if (!fp) return NULL;
	fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
	if (sz <= 0) { fclose(fp); return NULL; }
	unsigned char *b = malloc((size_t)sz);
	if (b && fread(b, 1, (size_t)sz, fp) != (size_t)sz) { free(b); b = NULL; }
	fclose(fp);
	*len = (size_t)sz;
	return b;
}

int main(int argc, char **argv)
{
	if (argc < 2) { fprintf(stderr, "usage: %s <file> [stream]\n", argv[0]); return 2; }
	size_t len;
	unsigned char *buf = slurp(argv[1], &len);
	if (!buf) { fprintf(stderr, "cannot read %s\n", argv[1]); return 2; }

	ole_file *f = ole_open(buf, len);
	if (!f) { fprintf(stderr, "ole_open failed (not a valid CFB?)\n"); free(buf); return 3; }

	if (argc >= 3) {
		const ole_entry *e = ole_find_stream(f, argv[2]);
		if (!e) { fprintf(stderr, "stream not found: %s\n", argv[2]); ole_close(f); free(buf); return 4; }
		size_t n;
		unsigned char *d = ole_read_stream(f, e, &n);
		if (!d) { fprintf(stderr, "read failed\n"); ole_close(f); free(buf); return 5; }
		fwrite(d, 1, n, stdout);
		free(d);
	} else {
		size_t i;
		for (i = 0; i < ole_num_entries(f); i++) {
			const ole_entry *e = ole_entry_at(f, i);
			if (e->type == 2)                          /* streams only */
				printf("%s\t%llu\n", e->name, (unsigned long long)e->size);
		}
	}
	ole_close(f);
	free(buf);
	return 0;
}
