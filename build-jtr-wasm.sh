#!/bin/bash
###############################################################################
# jtr-wasm build script — John the Ripper (archive password recovery) → WASM
#
# Scope: ZIP (ZipCrypto/PKZIP + WinZip-AES), RAR (rar3/rar5), 7z password
# recovery via the standard two-step flow (zip2john/rar2john/7z2john -> john
# --wordlist). Single binary; the 2john extractors are reached via argv[0]
# (set Module.thisProgram='/john/<tool>' at load — see post.js).
#
# Phase 1 = scalar baseline (--disable-simd). Pass `simd` as arg 1 to build the
# SIMD variant (Phase 3): ./build-jtr-wasm.sh simd
###############################################################################
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/john-bleeding-jumbo/src"
RUN="$SCRIPT_DIR/john-bleeding-jumbo/run"
OUT="$SCRIPT_DIR/output"
STAGE="$SCRIPT_DIR/build-stage"
NCPU="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)"

VARIANT="${1:-scalar}"   # scalar | simd

# --- 1. Emscripten env check ----------------------------------------------------
if ! command -v emcc &>/dev/null; then
  echo "❌ emcc not found. Activate the Emscripten SDK first, e.g.:"
  echo "     source /path/to/emsdk/emsdk_env.sh"
  echo "   (install: https://emscripten.org/docs/getting_started/downloads.html)"
  exit 1
fi
echo "✅ $(emcc --version | head -1)"

# --- 2. wasm-aware config.sub/config.guess (JtR's vendored copy may lack wasm) ----
# The shipped config.sub already understands wasm32-unknown-emscripten, so this
# block is normally skipped. It only runs if you replace it with an older copy:
# it then looks for a recent config.sub/config.guess (e.g. from GNU libtool /
# autotools) in a few common locations. Override with CFGAUX=/your/path if needed.
if [ "$(sh "$SRC/config.sub" wasm32-unknown-emscripten 2>/dev/null)" != "wasm32-unknown-emscripten" ]; then
  echo "📦 Installing wasm-aware config.sub/config.guess"
  for d in "$CFGAUX" /opt/homebrew/share/libtool/build-aux \
           /usr/local/share/libtool/build-aux /usr/share/libtool/build-aux \
           /usr/share/automake-*/ /usr/share/misc; do
    [ -f "$d/config.sub" ] && [ -f "$d/config.guess" ] && CFGAUX="$d" && break
  done
  if [ -z "$CFGAUX" ] || [ ! -f "$CFGAUX/config.sub" ]; then
    echo "❌ Could not find a wasm-aware config.sub/config.guess. Set CFGAUX=/path/to/build-aux"
    exit 1
  fi
  cp -n "$SRC/config.sub" "$SRC/config.sub.orig" 2>/dev/null || true
  cp -n "$SRC/config.guess" "$SRC/config.guess.orig" 2>/dev/null || true
  cp "$CFGAUX/config.sub" "$SRC/config.sub"
  cp "$CFGAUX/config.guess" "$SRC/config.guess"
fi

# --- 3. configure ---------------------------------------------------------------
cd "$SRC"
export CC=emcc CXX=em++ AR=emar RANLIB=emranlib NM=emnm
# -D_GNU_SOURCE: musl only declares strcasestr (and other GNU funcs JtR uses)
#   under _GNU_SOURCE; without it formats.c et al fail with implicit-decl errors.
# -DARCH_ALLOWS_UNALIGNED=1: wasm32 has no JtR arch header, so configure falls back
#   to autoconf_arch.h which leaves ARCH_ALLOWS_UNALIGNED undefined (=0). That gates
#   out the whole `rar` (RAR3/$RAR3$) + opencl_rar formats (rar_fmt_plug.c:48) so RAR4
#   archives can't be cracked. WASM supports unaligned memory access (alignment is a
#   load/store hint only), so =1 is the correct value: it registers `rar` and lets
#   shared crypto use the unaligned fast paths. MUST be a global CFLAGS define (not a
#   per-file patch) because md5.h/md4.h change MD5_CTX/MD4_CTX layout on this macro —
#   all TUs must agree or the struct ABI diverges. Requires a clean rebuild (below).
CFG_CFLAGS="-Os -fexceptions -D_GNU_SOURCE -DARCH_ALLOWS_UNALIGNED=1 -sUSE_ZLIB=1 -sUSE_BZIP2=1"
SIMD_OPT="--disable-simd"
if [ "$VARIANT" = "simd" ]; then
  # NOTE (deferred): JtR's --enable-simd=sse2 detection RUNS a compiled probe
  # (`./conftest` in configure), which can't execute under wasm cross-compile,
  # so configure aborts ("supports -msse2 w/ linking... no"). Enabling SIMD
  # needs a configure.ac patch turning that run-test into a compile/link test
  # (then verify hash/crack parity vs the scalar build). The scalar build is the
  # shipped, fully-validated artifact. See INTEGRATION.md / the plan.
  echo "⚠️  simd variant is not yet supported (configure run-test blocker) — building scalar."
  # (intentionally falling through to the scalar --disable-simd config)
fi
export CFLAGS="$CFG_CFLAGS"
export LDFLAGS="-sUSE_ZLIB=1 -sUSE_BZIP2=1"
echo "📦 configure ($VARIANT)"
emconfigure ./configure \
    --without-openssl $SIMD_OPT --disable-openmp \
    --disable-native-tests --disable-pcap \
    --host=wasm32-unknown-emscripten >/tmp/jtr-configure.log 2>&1

# Guardrail (reviewer): confirm zlib/bz2 macros are actually defined, else 7z
# silently loses DEFLATE/BZIP2 validation.
grep -q '#define HAVE_LIBZ 1'   autoconfig.h || { echo "❌ HAVE_LIBZ not set"; exit 1; }
grep -q '#define HAVE_LIBBZ2 1' autoconfig.h || { echo "❌ HAVE_LIBBZ2 not set"; exit 1; }
echo "   HAVE_LIBZ / HAVE_LIBBZ2: ok"

# --- 3b. clean rebuild (MANDATORY) ----------------------------------------------
# A CFLAGS-only change (e.g. -DARCH_ALLOWS_UNALIGNED=1) bumps no file mtime, so an
# incremental `make` keeps stale .o AND stale generated fmt_registers.h/fmt_externs.h
# (these depend only on .plugin_fmt_list — the plugin file *list*, not CFLAGS/content),
# meaning a newly-enabled format like `rar` would NOT register and the build would
# silently no-op. A partial rebuild is also an ABI hazard (md5.h/md4.h struct layout
# keys off ARCH_ALLOWS_UNALIGNED). So always clean first. `make clean` removes
# fmt_registers.h/fmt_externs.h, *.o, lzma/*.o, ../run/john, and subdir .a/.o.
echo "🧹 make clean (forces full rebuild so flag/header changes take effect)"
emmake make -j"$NCPU" clean

# --- 4. stage the /john config home (john.conf + full <...> include closure) -----
# The closure is entirely *.conf files + the rules/ dir (verified); staging those
# (and NOT password.lst / *.chr) keeps the preloaded .data small (~3 MB).
echo "📦 staging /john config home"
rm -rf "$STAGE/john-home"; mkdir -p "$STAGE/john-home"
cp "$RUN"/*.conf "$STAGE/john-home/"
cp -r "$RUN"/rules "$STAGE/john-home/rules"

# --- 5. build ../run/john (emcc emits JS + .wasm + .data) ------------------------
EMFLAGS="-g -sUSE_ZLIB=1 -sUSE_BZIP2=1 \
-fexceptions -sDISABLE_EXCEPTION_CATCHING=0 \
-sMODULARIZE=1 -sEXPORT_NAME=JohnTheRipper -sENVIRONMENT=web,webview,worker,node \
-sEXPORTED_FUNCTIONS=['_main','_malloc','_free'] \
-sEXPORTED_RUNTIME_METHODS=['FS','WORKERFS','NODEFS','callMain','ccall','cwrap','stringToUTF8','getExceptionMessage'] \
-sINITIAL_MEMORY=268435456 -sMAXIMUM_MEMORY=4294836224 -sALLOW_MEMORY_GROWTH=1 -sSTACK_SIZE=134217728 \
-sFILESYSTEM=1 -sFORCE_FILESYSTEM=1 -sEXIT_RUNTIME=0 -sINVOKE_RUN=0 \
-lworkerfs.js -lnodefs.js \
--post-js $SCRIPT_DIR/post.js \
--preload-file $STAGE/john-home@/john"

echo "🏗️  building john (this compiles ~300 objects, be patient)"
emmake make -j"$NCPU" ../run/john LDFLAGS="$EMFLAGS"

# --- 6. publish to output/ as jtr.js + jtr.wasm + jtr.data ----------------------
mkdir -p "$OUT"
cp "$RUN/john"      "$OUT/jtr.js"
cp "$RUN/john.wasm" "$OUT/jtr.wasm"
cp "$RUN/john.data" "$OUT/jtr.data"
# emcc bakes the output basename into the JS (references "john.wasm"/"john.data").
sed -i '' 's/john\.wasm/jtr.wasm/g; s/john\.data/jtr.data/g' "$OUT/jtr.js"
# Make the preloaded-data loader self-locate in Node when no locateFile is given
# (emscripten injects the package loader before --pre-js, so this can't be a
# pre-js default). Browsers still pass their own locateFile. Keeps `node
# test-nodefs-contract.js .../jtr.js` working from any cwd.
node -e '
const fs=require("fs"); const f=process.argv[1]; let s=fs.readFileSync(f,"utf8");
s=s.replace(
  /Module\["locateFile"\] \? Module\["locateFile"\]\(REMOTE_PACKAGE_BASE, ""\) : REMOTE_PACKAGE_BASE;/,
  `Module["locateFile"] ? Module["locateFile"](REMOTE_PACKAGE_BASE, "") : (typeof __dirname !== "undefined" ? require("path").join(__dirname, REMOTE_PACKAGE_BASE) : REMOTE_PACKAGE_BASE);`
);
fs.writeFileSync(f,s);
' "$OUT/jtr.js"

echo "✅ done:"
ls -lh "$OUT"/jtr.js "$OUT"/jtr.wasm "$OUT"/jtr.data
echo "   (default wordlist run/password.lst is shipped separately, on demand)"
