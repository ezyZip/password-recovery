/*
 * ole2.h — minimal read-only OLE2 / CFB (Compound File Binary, MS-CFB) reader
 * for the jtr-wasm office2john port. Encrypted .doc/.xls/.ppt AND the modern
 * .docx/.xlsx/.pptx (whose encrypted form is an OLE2 container with
 * EncryptionInfo + EncryptedPackage streams) are all CFB files, so a single
 * reader serves both eras. No external deps; bounds- and cycle-checked; never
 * aborts — malformed input returns NULL.
 */
#ifndef JTR_OLE2_H
#define JTR_OLE2_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
	char     name[64];     /* ASCII-folded UTF-16LE entry name, NUL-terminated */
	int      type;         /* 1=storage, 2=stream, 5=root */
	uint32_t start;        /* first (mini)sector of the stream */
	uint64_t size;         /* stream length in bytes */
} ole_entry;

typedef struct ole_file ole_file;

/* Parse an in-memory CFB image (buf must outlive the returned handle; not
 * copied, not owned). Returns NULL on any malformed/unsupported input. */
ole_file *ole_open(const uint8_t *buf, size_t len);

/* First directory entry whose ASCII name exactly matches `name` (case
 * sensitive, like python olefile). NULL if absent. */
const ole_entry *ole_find_stream(ole_file *f, const char *name);

/* Materialize a stream's bytes into a fresh malloc'd buffer (caller free()s).
 * *out_len receives the byte length. NULL on corruption / cycle / OOM. */
uint8_t *ole_read_stream(ole_file *f, const ole_entry *e, size_t *out_len);

/* Number of directory entries (for listing / contract tests). */
size_t ole_num_entries(const ole_file *f);
const ole_entry *ole_entry_at(const ole_file *f, size_t i);

void ole_close(ole_file *f);

#endif /* JTR_OLE2_H */
