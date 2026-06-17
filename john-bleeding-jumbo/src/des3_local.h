/*
 * des3_local.h — minimal OpenSSL-compatible 3DES (DES-EDE3-CBC) for the
 * jtr-wasm build, which configures --without-openssl (no libcrypto).
 *
 * Provides exactly the subset of the OpenSSL DES API that dmg_fmt_plug.c uses
 * so the `dmg` format can crack Apple FileVault images (both v1 and v2 unwrap
 * the key blob with 3DES) without OpenSSL. The bundled `aes.h` already supplies
 * AES via mbedtls and `pbkdf2_hmac_sha1.h`/`hmac_sha.h` supply the SHA1 parts;
 * 3DES was the only remaining libcrypto dependency.
 *
 * This is a textbook table-driven DES (FIPS 46-3), verified against the
 * canonical DES known-answer vector and the end-to-end DMG crack. Speed is a
 * non-issue: DMG spends its time in PBKDF2-SHA1, then runs only a few DES
 * blocks per candidate.
 *
 * Only included when !HAVE_LIBCRYPTO (see dmg_fmt_plug.c). When OpenSSL is
 * present the real <openssl/des.h> is used instead.
 */
#ifndef JTR_DES3_LOCAL_H
#define JTR_DES3_LOCAL_H

#include <stddef.h>

/* OpenSSL-compatible types */
typedef unsigned char DES_cblock[8];
typedef unsigned char const_DES_cblock[8];

/* 16 round subkeys, 48 bits each, one bit per byte (correctness over size) */
typedef struct {
	unsigned char sk[16][48];
} DES_key_schedule;

#define DES_ENCRYPT 1
#define DES_DECRYPT 0

/* Build a key schedule from an 8-byte key (parity bits ignored, "unchecked"). */
void DES_set_key_unchecked(const_DES_cblock *key, DES_key_schedule *schedule);

/*
 * DES-EDE3 in CBC mode, matching OpenSSL semantics:
 *   enc == DES_ENCRYPT : C = E_ks3(D_ks2(E_ks1(P ^ iv))) chained
 *   enc == DES_DECRYPT : P = D_ks1(E_ks2(D_ks3(C))) ^ iv chained
 * Processes floor(length/8) 8-byte blocks (DMG key blobs are multiples of 8).
 * *ivec is updated to the last cipher block, like OpenSSL.
 */
void DES_ede3_cbc_encrypt(const unsigned char *input, unsigned char *output,
                          long length,
                          DES_key_schedule *ks1, DES_key_schedule *ks2,
                          DES_key_schedule *ks3,
                          DES_cblock *ivec, int enc);

#endif /* JTR_DES3_LOCAL_H */
