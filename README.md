# password-recovery — John the Ripper → WebAssembly

A WebAssembly build of [John the Ripper](https://github.com/openwall/john)
(jumbo), scoped to **password recovery** for encrypted **archives (ZIP, RAR, 7z)**,
Apple **disk images (DMG)**, **PDF** documents, and Microsoft **Office** documents
(Word, Excel, PowerPoint). It runs entirely in Node.js or the browser (Web Worker)
with no native binaries.

Recovery uses JtR's standard **two-step flow**:

1. A `*2john` extractor reads the file header and prints a `$fmt$…` **hash
   string** (`zip2john`, `rar2john`, `7z2john`, `dmg2john`, `pdf2john`,
   `office2john`).
2. `john --wordlist` cracks that hash against a wordlist to recover the password.

Both steps are the **same binary**, selected at load time by `argv[0]`
(`Module.thisProgram = '/john/<tool>'`) — see [`post.js`](post.js).

### Verified formats

**Archives** — ZipCrypto (`$pkzip$`), WinZip-AES (`$zip2$`), **RAR4** (`$RAR3$` —
both `-p` data-encrypted and `-hp` header-encrypted modes), **RAR5** (`$rar5$`,
including solid and header-encrypted), and **7z** (`$7z$`:
LZMA1/LZMA2/COPY/BZIP2/DEFLATE, plain or LZMA-encoded headers, single and solid
multi-file). Out-of-scope archive inputs (header-encrypted 7z `-mhe=on`,
BCJ/Delta/PPMD filters, split/SFX archives) fail cleanly without crashing.

**DMG** (`$dmg$` → `--format=dmg`) — Apple encrypted disk images, v1 and v2
(AES-128 / AES-256, `hdiutil`-created).

**PDF** (`$pdf$` → `--format=PDF`) — the standard security handler: RC4-40/128
(R2/R3), AES-128 (R4), AES-256 (R6), incremental-update and EncryptMetadata-false
files. Public-key (`/PubSec`) PDFs fail cleanly.

**Office** (extractor `office2john`) — modern OOXML **Word, Excel and PowerPoint**
(`.docx` / `.xlsx` / `.pptx`, agile encryption → `$office$`, `--format=Office`;
2007 / 2010 / 2013) and legacy **Word / Excel** (`.doc` / `.xls`, RC4 →
`$oldoffice$`, `--format=oldoffice`). All three modern apps share one OOXML/CFB code
path, validated here by the committed `office-agile-2013.docx` baseline; legacy
`.doc`/`.xls` are exercised by the optional openwall corpus, and legacy `.ppt` is
parsed by `office2john` but is fixture-limited (best-effort). XOR-obfuscated Office
files fail cleanly.

---

## Live demo

This build powers the in-browser password recovery tools at
[ezyZip](https://www.ezyzip.com), which run entirely client-side (your files
never leave your device):

- [Recover ZIP password](https://www.ezyzip.com/recover-zip-password.html)
- [Recover 7z password](https://www.ezyzip.com/recover-7z-password.html)
- [Recover RAR password](https://www.ezyzip.com/recover-rar-password.html)
- [Recover DMG password](https://www.ezyzip.com/recover-dmg-password.html)
- [Recover PDF password](https://www.ezyzip.com/recover-pdf-password.html)
- [Recover Word password](https://www.ezyzip.com/recover-word-password.html)
- [Recover Excel password](https://www.ezyzip.com/recover-excel-password.html)
- [Recover PowerPoint password](https://www.ezyzip.com/recover-powerpoint-password.html)

---

## License

This project is distributed under the **GNU General Public License v2** (see
[`LICENSE`](LICENSE)).

It builds on **John the Ripper (jumbo)**, © Openwall and contributors, which is
itself GPLv2 with linking exceptions for OpenSSL and unRAR. The complete upstream
license text is preserved at
[`john-bleeding-jumbo/doc/LICENSE`](john-bleeding-jumbo/doc/LICENSE) and
[`john-bleeding-jumbo/doc/COPYING`](john-bleeding-jumbo/doc/COPYING). Upstream
source: <https://github.com/openwall/john> (bleeding-jumbo branch).

### Changes from upstream John the Ripper

For GPL transparency, the modifications made to the vendored JtR tree are:

- **New file** `john-bleeding-jumbo/src/7z2john.c` — a C port of the upstream
  `run/7z2john.pl` script (emits the `$7z$…` hash; reuses the in-tree LZMA decoder
  for LZMA-encoded headers).
- **New files** `src/pdf2john.c`, `src/office2john.c` (plus `src/ole2.c` /
  `src/ole2.h`, a minimal read-only OLE2 / CFB reader) — C ports of the upstream
  `run/pdf2john.py` and `run/office2john.py` scripts, since the WASM build cannot run
  Python. They do pure parsing and emit the `$pdf$…` / `$office$…` / `$oldoffice$…`
  hash; all crypto stays in the cracker plugins.
- **New files** `src/des3_local.c` / `src/des3_local.h` — a compact, KAT-verified,
  OpenSSL-API-compatible 3DES (DES-EDE3-CBC). The `dmg` format unwraps its key blob
  with 3DES (v1 and v2); this build configures `--without-openssl`, so it supplies
  3DES locally (AES / HMAC-SHA1 / PBKDF2 already come from the bundled
  `aes.h` / `hmac_sha.h`).
- **`src/dmg_fmt_plug.c`** — un-gate the format from `#if HAVE_LIBCRYPTO` so it
  builds without libcrypto, using `des3_local.h` for 3DES.
- **`src/dmg2john.c`** — add an `int dmg2john(int, char**)` entry point for the
  `argv[0]` dispatch (the native standalone `main()` is kept for non-WASM builds).
- **`src/john.c`** — dispatch `argv[0]` to the C extractors above (`7z2john`,
  `dmg2john`, `pdf2john`, `office2john`).
- **`src/Makefile.in`** — add `7z2john.o`, `dmg2john.o`, `des3_local.o`,
  `pdf2john.o`, `office2john.o` and `ole2.o` to the build.
- **`src/status.c`, `src/status.h`, `src/cracker.c`** — a `status_emit_wasm_progress()`
  hook (all guarded by `#ifdef __EMSCRIPTEN__`) that streams live candidate counts
  to JavaScript, because JtR's native `SIGALRM`/`times()`-driven status reporting
  does not fire during a synchronous WASM run.
- **`src/config.sub` / `src/config.guess`** — updated to versions that recognize
  the `wasm32-unknown-emscripten` host triple.

The WASM build glue — `build-jtr-wasm.sh`, `post.js`, and everything under
`test/` — is original to this project and also GPLv2.

---

## Repository layout

```
.
├── build-jtr-wasm.sh        # the build script (Emscripten + autoconf)
├── post.js                  # JS glue appended to the Emscripten module
├── test-nodefs-contract.js  # FS/WORKERFS/NODEFS smoke test
├── test/                    # Node + browser test harnesses
└── john-bleeding-jumbo/     # John the Ripper (jumbo) source — modified, see above
```

> This repository contains **source only**. No compiled WebAssembly, `.js`, `.data`
> or object files are checked in — you build them yourself (below).

---

## Prerequisites

- **[Emscripten SDK](https://emscripten.org/docs/getting_started/downloads.html)**
  (emsdk), activated so that `emcc` is on your `PATH`. Tested with Emscripten
  **5.0.x**. Activate with:

  ```bash
  source /path/to/emsdk/emsdk_env.sh
  ```

- A POSIX shell, `make`, and the standard autotools toolchain. On macOS this comes
  with the Xcode command-line tools and Homebrew; on Linux with `build-essential`.
- *(Optional, for the test suite only)* the native `zip`, `7zz`/`7z` and `rar`
  command-line tools — used to generate encrypted test fixtures on the fly.

---

## Build

```bash
source /path/to/emsdk/emsdk_env.sh   # make `emcc` available
./build-jtr-wasm.sh                  # scalar build
```

This produces:

| File | Approx. size | Contents |
|------|-------------|----------|
| `output/jtr.js`   | ~200 KB | Emscripten loader + glue |
| `output/jtr.wasm` | ~5 MB   | the compiled module |
| `output/jtr.data` | ~3 MB   | preloaded JtR config closure (`*.conf` + `rules/`) |

### Build notes

- The build configures with `emconfigure ./configure --without-openssl
  --disable-simd --disable-openmp --disable-native-tests --disable-pcap`.
- `-D_GNU_SOURCE` is required (musl only declares `strcasestr` and friends under it).
- `-DARCH_ALLOWS_UNALIGNED=1` is required to crack RAR4: wasm32 has no JtR arch
  header, so configure falls back to a header that leaves this macro at 0, which
  gates out the entire `rar` format. WASM permits unaligned access, so `=1` is
  correct. Because this flag also keys `MD5_CTX`/`MD4_CTX` struct layout, it must be
  global and the script does a clean rebuild so it takes effect everywhere.
- A SIMD variant (`./build-jtr-wasm.sh simd`) is stubbed but **not yet supported**
  (JtR's SIMD autodetection runs a compiled probe, which cannot execute under a
  WASM cross-compile). The scalar build is the validated artifact.

---

## Test

```bash
node test/test-jtr-node.js                              # ZIP/RAR/7z NODEFS two-step matrix
node test/test-jtr-formats-node.js                      # DMG/PDF/Office baseline (committed fixtures)
node test-nodefs-contract.js output/jtr.js output       # FS/WORKERFS/NODEFS contract
node test/browser/serve.js 8097                          # browser harness → http://localhost:8097
```

The archive suite (`test-jtr-node.js`) generates its own encrypted fixtures with the
native `zip`/`7zz`/`rar` tools; cases whose tool is missing are skipped, not failed.
The DMG/PDF/Office suite (`test-jtr-formats-node.js`) is anchored on committed,
license-clean, self-generated fixtures under `test/fixtures/`, each with a golden
`.hash` sidecar (a missing baseline fixture is a failure, never a silent skip); if
`pyhanko`/`olefile` are importable it also asserts live byte-parity against the
reference `run/*2john.py`. Optional real-world legacy/2007 Office samples come from
the openwall `john-samples` corpus (unlicensed, **not committed**) — run
`test/fetch-office-corpus.sh` to populate the gitignored `test/fixtures/office-corpus/`.
The OLE2/CFB reader has its own parity gate against python `olefile`:

```bash
python3 test/test-ole2-contract.py test/fixtures/office-agile-2013.docx test/fixtures/office-agile-large.docx
```

---

## Wordlist

A wordlist is **not bundled** (to keep the repository small). Supply your own, or
fetch the default John the Ripper list from upstream:
[`run/password.lst`](https://github.com/openwall/john/blob/bleeding-jumbo/run/password.lst).

---

## Usage

The CLI tools keep global state and are not re-entrant, so each step runs in a
**fresh module instance**. Pass arguments **without** `argv[0]` — Emscripten
supplies it from `Module.thisProgram`.

```js
const JohnTheRipper = require('./output/jtr.js');

// Step 1 — extract the hash (no config needed)
const ex = await JohnTheRipper({
  thisProgram: '/john/zip2john',          // or rar2john / 7z2john / dmg2john / pdf2john / office2john
  noInitialRun: true,
  print: s => hashOut.push(s),
});
// Node: mount the host dir holding the archive
ex.FS.mount(ex.NODEFS, { root: '/path/to/dir' }, '/in');
ex.callMain(['/in/archive.zip']);          // hash printed via `print`
const hash = ex.firstHashLine(hashOut);

// Step 2 — crack it (config is preloaded at /john from jtr.data)
const jn = await JohnTheRipper({
  thisProgram: '/john/john',
  noInitialRun: true,
  print: s => crackOut.push(s),
});
jn.FS.writeFile('/h', hash + '\n');
jn.FS.writeFile('/w', 'foo\nbar\nhunter2\n');   // or mount a big list via WORKERFS
jn.callMain(['--wordlist=/w', '--format=' + jn.formatFromHash(hash),
             '--pot=/jtr.pot', '--session=/s', '/h']);
// recovered password is in crackOut (strip ANSI color codes if present)
```

In the browser/worker, mount the archive and wordlist read-only via **WORKERFS**
(`Module.mountArchive(file)` / `Module.mountWordlist(file)` in `post.js`) so they
are streamed rather than copied into the WASM heap.

### Live progress (optional)

Set `Module.onCrackProgress = (count) => { ... }` before `callMain` to receive a
running candidate count during cracking (throttled to ~7 updates/sec). Compute
rate/ETA on the JS side using `Date.now()` and your wordlist line count.

### Worker message protocol (reference)

A self-contained worker that performs the full two-step might expose:

```ts
// → worker
{ method: 'recover', archiveFile: File,
  wordlistFile?: File,        // optional; falls back to a bundled/supplied list
  maxRunTimeSec?: number }    // optional cap (john --max-run-time)
// ← worker
{ type: 'progress', phase: 'extract' | 'crack', message?: string,
  tried?: number, total?: number, percent?: number, rate?: number, etaSec?: number }
{ type: 'result', found: boolean, password?: string, format?: string }
{ type: 'error', error: string }
```

---

## Notes & scope

- **Single-threaded**, no Asyncify, no OPFS — the only output is a short password
  string read from stdout, so memory use is bounded by the decompressor's working
  set, not by input file size.
- WASM crypto is slower than native; wordlist attacks against modest lists are
  practical. 7z, RAR5, PDF (AES-256/R6) and modern Office (agile) use heavy PBKDF2
  and are slower per candidate — use `maxRunTimeSec` (`john --max-run-time`) to bound
  long runs.
- This is a **defensive / recovery** tool: recover the password to a file you
  own or are authorized to access.
