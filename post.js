/**
 * jtr-wasm post.js
 *
 * Appended after the Emscripten runtime (MODULARIZE, EXPORT_NAME='JohnTheRipper').
 * John the Ripper, scoped to archive password recovery (zip/rar/7z).
 *
 * Usage model — the "two-step" + "fresh module per command":
 *   John is ONE binary that acts as zip2john/rar2john/7z2john/john depending on
 *   argv[0]. In WASM, argv[0] is Module.thisProgram, set at construction. These
 *   CLI tools keep global state and aren't re-entrant, so each step is a FRESH
 *   module instance:
 *
 *     // step 1 — extract the hash (no config needed)
 *     const ex = await JohnTheRipper({ thisProgram: '/john/' + tool,
 *                  noInitialRun: true, print: s => hashOut.push(s) });
 *     ex.mountArchive(file, '/in');            // WORKERFS (worker) ...
 *     ex.callMain(['/in/' + file.name]);       // ... or FS.mount(NODEFS,...) in node
 *
 *     // step 2 — crack it (config is PRELOADED at /john from jtr.data)
 *     const jn = await JohnTheRipper({ thisProgram: '/john/john',
 *                  noInitialRun: true, print: s => crackOut.push(s) });
 *     jn.FS.writeFile('/h', hashLine + '\n');
 *     jn.FS.writeFile('/w', wordlistText);     // or mount a big list via WORKERFS
 *     jn.callMain(['--wordlist=/w', '--format=' + fmt,
 *                  '--pot=/p.pot', '--session=/s', '/h']);
 *
 *   thisProgram MUST be a full path like '/john/zip2john': john derives both the
 *   tool (basename) and its config home $JOHN (dirname) from argv[0]. The config
 *   closure is preloaded into /john (jtr.data), so cracking is self-contained.
 *
 * No Asyncify, no OPFS backend: the only output is the recovered password, read
 * from stdout (the caller's `print`) or the pot file. Input archive + wordlist
 * mount read-only via WORKERFS (browser worker) / NODEFS (node) — off heap.
 */

// === FS exports — required contract =====================
Module.FS = FS;
Module.WORKERFS = WORKERFS;
Module.NODEFS = NODEFS;

// === Synchronous callMain with C++ exception decoding ======================
// Emscripten supplies argv[0] from Module.thisProgram; pass args WITHOUT it,
// e.g. Module.callMain(['/in/archive.7z']) or Module.callMain(['--wordlist=...','/h'])
const _rawCallMain = Module.callMain;
Module._rawCallMain = _rawCallMain;
Module.callMain = function (args) {
    try {
        return _rawCallMain(args);
    } catch (e) {
        if (typeof getExceptionMessage === 'function') {
            try {
                const [type, msg] = getExceptionMessage(e);
                console.error('C++ Exception [' + type + ']:', msg);
                const err = new Error(msg || type || 'jtr error');
                err.cppType = type;
                throw err;
            } catch (_) {
                // getExceptionMessage failed — fall through to raw throw.
            }
        }
        throw e;
    }
};

// === Input mounting (no heap copy) =========================================
// Mount the input archive (and any extra files, e.g. a user wordlist) read-only
// via WORKERFS. Worker-only (WORKERFS needs FileReaderSync). Returns the in-VFS
// path of the first file. For Node, use FS.mount(NODEFS, {root}, mountPath).
Module.mountArchive = function (files, mountPath) {
    mountPath = mountPath || '/in';
    if (!Array.isArray(files)) files = [files];
    if (!Module.FS.analyzePath(mountPath).exists) {
        Module.FS.mkdir(mountPath);
    }
    Module.FS.mount(Module.WORKERFS, { files: files }, mountPath);
    return mountPath + '/' + files[0].name;
};

// Mount a (possibly huge) wordlist File/Blob read-only via WORKERFS so it is
// streamed, never copied into the WASM heap. Returns its in-VFS path.
Module.mountWordlist = function (file, mountPath) {
    mountPath = mountPath || '/words';
    if (!Module.FS.analyzePath(mountPath).exists) {
        Module.FS.mkdir(mountPath);
    }
    Module.FS.mount(Module.WORKERFS, { files: [file] }, mountPath);
    return mountPath + '/' + file.name;
};

// === Format detection ======================================================
// Pick the right extractor ("*2john" tool) from a filename. The frontend
// already knows the archive kind; this keeps that mapping in one place.
Module.detectTool = function (filename) {
    const n = String(filename).toLowerCase();
    if (n.endsWith('.7z')) return '7z2john';
    if (n.endsWith('.rar')) return 'rar2john';
    if (n.endsWith('.zip') || n.endsWith('.zipx')) return 'zip2john';
    // default: zip is the most common; caller may override
    return 'zip2john';
};

// Map a produced hash line to john's --format value. John can auto-detect, but
// being explicit avoids "multiple format" ambiguity warnings. Returns null if
// unknown (let john auto-detect).
Module.formatFromHash = function (hashLine) {
    const h = String(hashLine);
    const i = h.indexOf('$');
    const s = i >= 0 ? h.slice(i) : h;
    if (s.startsWith('$7z$')) return '7z';
    if (s.startsWith('$zip2$')) return 'ZIP';        // WinZip AES
    if (s.startsWith('$pkzip$') || s.startsWith('$pkzip2$')) return 'PKZIP'; // ZipCrypto
    if (s.startsWith('$rar5$')) return 'rar5';
    if (s.startsWith('$RAR3$') || s.startsWith('$rar$')) return 'rar';       // RAR3
    return null;
};

// Extract just the hash portion (john accepts the whole "name:hash:..." line,
// but a trimmed first non-empty stdout line is what callers usually want).
Module.firstHashLine = function (stdoutLines) {
    const arr = Array.isArray(stdoutLines) ? stdoutLines : String(stdoutLines).split('\n');
    for (const l of arr) {
        const t = (l || '').trim();
        if (t && t.indexOf('$') >= 0) return t;
    }
    return '';
};
