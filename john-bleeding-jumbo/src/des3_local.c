/*
 * des3_local.c — compact, table-driven DES / DES-EDE3-CBC (FIPS 46-3) used by
 * the jtr-wasm build when compiled --without-openssl. See des3_local.h.
 *
 * Bit ordering: a 64-bit block is treated MSB-first; bit 1 of the standard
 * tables is the most-significant bit of byte 0. All permutation tables below
 * are the canonical DES tables (1-based, as published in FIPS 46-3).
 */
#include <string.h>
#include "des3_local.h"

/* Initial Permutation */
static const unsigned char IP[64] = {
	58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
	62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
	57,49,41,33,25,17,9,1,  59,51,43,35,27,19,11,3,
	61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
};

/* Final Permutation (inverse of IP) */
static const unsigned char FP[64] = {
	40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
	38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
	36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
	34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25
};

/* Expansion (32 -> 48) */
static const unsigned char E[48] = {
	32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13, 12,13,14,15,16,17,
	16,17,18,19,20,21, 20,21,22,23,24,25, 24,25,26,27,28,29, 28,29,30,31,32,1
};

/* P permutation (32 -> 32) inside the f-function */
static const unsigned char P[32] = {
	16,7,20,21,29,12,28,17, 1,15,23,26,5,18,31,10,
	2,8,24,14,32,27,3,9,    19,13,30,6,22,11,4,25
};

/* Permuted Choice 1 (64 -> 56) */
static const unsigned char PC1[56] = {
	57,49,41,33,25,17,9, 1,58,50,42,34,26,18,
	10,2,59,51,43,35,27, 19,11,3,60,52,44,36,
	63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
	14,6,61,53,45,37,29, 21,13,5,28,20,12,4
};

/* Permuted Choice 2 (56 -> 48) */
static const unsigned char PC2[48] = {
	14,17,11,24,1,5, 3,28,15,6,21,10, 23,19,12,4,26,8, 16,7,27,20,13,2,
	41,52,31,37,47,55, 30,40,51,45,33,48, 44,49,39,56,34,53, 46,42,50,36,29,32
};

/* Left rotations per round */
static const unsigned char SHIFTS[16] = {
	1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
};

/* The eight S-boxes, each 4 rows x 16 cols (row-major) */
static const unsigned char SBOX[8][64] = {
	{ /* S1 */
	14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
	0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
	4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
	15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 },
	{ /* S2 */
	15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
	3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
	0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
	13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 },
	{ /* S3 */
	10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
	13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
	13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
	1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 },
	{ /* S4 */
	7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
	13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
	10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
	3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 },
	{ /* S5 */
	2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
	14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
	4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
	11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 },
	{ /* S6 */
	12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
	10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
	9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
	4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 },
	{ /* S7 */
	4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
	13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
	1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
	6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 },
	{ /* S8 */
	13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
	1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
	7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
	2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
};

static void bytes_to_bits(const unsigned char *in, unsigned char *bits, int n)
{
	int i;
	for (i = 0; i < n; i++)
		bits[i] = (in[i >> 3] >> (7 - (i & 7))) & 1;
}

static void bits_to_bytes(const unsigned char *bits, unsigned char *out, int n)
{
	int i;
	memset(out, 0, (n + 7) >> 3);
	for (i = 0; i < n; i++)
		out[i >> 3] |= bits[i] << (7 - (i & 7));
}

static void permute(const unsigned char *in, const unsigned char *table,
                    unsigned char *out, int n)
{
	int i;
	for (i = 0; i < n; i++)
		out[i] = in[table[i] - 1];
}

void DES_set_key_unchecked(const_DES_cblock *key, DES_key_schedule *schedule)
{
	unsigned char keybits[64];
	unsigned char cd[56];   /* C (28) || D (28) after PC1 */
	int r, i, s;

	bytes_to_bits((const unsigned char *)key, keybits, 64);
	permute(keybits, PC1, cd, 56);

	for (r = 0; r < 16; r++) {
		/* rotate C (cd[0..27]) and D (cd[28..55]) left by SHIFTS[r] */
		for (s = 0; s < SHIFTS[r]; s++) {
			unsigned char c0 = cd[0], d0 = cd[28];
			for (i = 0; i < 27; i++) {
				cd[i] = cd[i + 1];
				cd[28 + i] = cd[28 + i + 1];
			}
			cd[27] = c0;
			cd[55] = d0;
		}
		permute(cd, PC2, schedule->sk[r], 48);
	}
}

/* f-function: R (32 bits) and a 48-bit subkey -> 32 bits */
static void des_f(const unsigned char *r32, const unsigned char *subkey,
                  unsigned char *out32)
{
	unsigned char er[48];
	unsigned char sout[32];
	int i, b;

	permute(r32, E, er, 48);
	for (i = 0; i < 48; i++)
		er[i] ^= subkey[i];

	for (b = 0; b < 8; b++) {
		const unsigned char *g = er + b * 6;
		int row = (g[0] << 1) | g[5];
		int col = (g[1] << 3) | (g[2] << 2) | (g[3] << 1) | g[4];
		int v = SBOX[b][row * 16 + col];
		sout[b * 4 + 0] = (v >> 3) & 1;
		sout[b * 4 + 1] = (v >> 2) & 1;
		sout[b * 4 + 2] = (v >> 1) & 1;
		sout[b * 4 + 3] = v & 1;
	}
	permute(sout, P, out32, 32);
}

/* Single DES on one 8-byte block. decrypt!=0 runs subkeys in reverse order. */
static void des_block(const unsigned char *in, unsigned char *out,
                      const DES_key_schedule *ks, int decrypt)
{
	unsigned char bits[64], perm[64];
	unsigned char L[32], R[32], f[32], newR[32];
	int r, i;

	bytes_to_bits(in, bits, 64);
	permute(bits, IP, perm, 64);
	memcpy(L, perm, 32);
	memcpy(R, perm + 32, 32);

	for (r = 0; r < 16; r++) {
		const unsigned char *sk = ks->sk[decrypt ? (15 - r) : r];
		des_f(R, sk, f);
		for (i = 0; i < 32; i++)
			newR[i] = L[i] ^ f[i];
		memcpy(L, R, 32);
		memcpy(R, newR, 32);
	}

	/* preoutput is R || L (32-bit halves swapped) */
	memcpy(perm, R, 32);
	memcpy(perm + 32, L, 32);
	permute(perm, FP, bits, 64);
	bits_to_bytes(bits, out, 64);
}

/* DES-EDE3 on one block (in place into out). */
static void des_ede3_block(const unsigned char *in, unsigned char *out,
                           const DES_key_schedule *ks1,
                           const DES_key_schedule *ks2,
                           const DES_key_schedule *ks3, int enc)
{
	unsigned char a[8], b[8];

	if (enc == DES_ENCRYPT) {
		des_block(in, a, ks1, 0);  /* E_ks1 */
		des_block(a, b, ks2, 1);   /* D_ks2 */
		des_block(b, out, ks3, 0); /* E_ks3 */
	} else {
		des_block(in, a, ks3, 1);  /* D_ks3 */
		des_block(a, b, ks2, 0);   /* E_ks2 */
		des_block(b, out, ks1, 1); /* D_ks1 */
	}
}

void DES_ede3_cbc_encrypt(const unsigned char *input, unsigned char *output,
                          long length,
                          DES_key_schedule *ks1, DES_key_schedule *ks2,
                          DES_key_schedule *ks3,
                          DES_cblock *ivec, int enc)
{
	unsigned char iv[8];
	long off;
	int i;

	memcpy(iv, ivec, 8);

	if (enc == DES_ENCRYPT) {
		for (off = 0; off + 8 <= length; off += 8) {
			unsigned char in[8], out[8];
			for (i = 0; i < 8; i++)
				in[i] = input[off + i] ^ iv[i];
			des_ede3_block(in, out, ks1, ks2, ks3, DES_ENCRYPT);
			memcpy(output + off, out, 8);
			memcpy(iv, out, 8);   /* chain on ciphertext */
		}
	} else {
		for (off = 0; off + 8 <= length; off += 8) {
			unsigned char cblk[8], out[8];
			memcpy(cblk, input + off, 8);          /* save ciphertext */
			des_ede3_block(cblk, out, ks1, ks2, ks3, DES_DECRYPT);
			for (i = 0; i < 8; i++)
				output[off + i] = out[i] ^ iv[i];
			memcpy(iv, cblk, 8);  /* chain on ciphertext */
		}
	}

	memcpy(ivec, iv, 8);  /* match OpenSSL: ivec advanced to last block */
}
