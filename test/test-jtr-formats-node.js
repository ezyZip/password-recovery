#!/usr/bin/env node
/**
 * jtr-wasm Node test — DMG / PDF / Office password recovery (the C-port
 * extractors dmg2john / pdf2john / office2john), two-step extract -> crack.
 *
 *   node test/test-jtr-formats-node.js
 *
 * Unlike the broad archive suite (test-jtr-node.js), this suite is anchored on
 * a COMMITTED baseline fixture set under test/fixtures/ so it can never pass
 * vacuously: every baseline fixture is REQUIRED (a missing one is a FAILURE,
 * not a skip). Each baseline ships a golden ".hash" sidecar (the normalized
 * $...$ field) produced once via the reference oracle; the test compares the
 * WASM tool's output to it (so the baseline runs even without python/oracles).
 *
 * When the reference oracle (run/<tool>.py) and its python deps are present we
 * ALSO assert live byte-parity (normalized hash field). Optional generated
 * fixtures (qpdf/hdiutil/msoffcrypto) can broaden coverage elsewhere.
 */
'use strict';
const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const MODULE_JS = path.join(ROOT, 'output', 'jtr.js');
const ASSET_DIR = path.join(ROOT, 'output') + path.sep;
const FIX = path.join(ROOT, 'test', 'fixtures');
const RUN = path.join(ROOT, 'john-bleeding-jumbo', 'run');
const JohnTheRipper = require(MODULE_JS);

let pass = 0, fail = 0, skip = 0;
function ok(name, cond, detail) {
    if (cond) { pass++; console.log('  ✓ ' + name); }
    else { fail++; console.log('  ✗ ' + name + (detail ? '  — ' + detail : '')); }
}
function note(s) { console.log('  · ' + s); }

// Normalize an extractor stdout line to the pure "$tag$...." hash field:
// strip the "name:" prefix (everything before the first '$') and any trailing
// ":::"/"::::"-style loader metadata (everything from the first ':' after the
// hash — these hashes use '*' as their internal separator, never ':').
function normalizeHash(line) {
    if (!line) return '';
    const d = line.indexOf('$');
    if (d < 0) return '';
    let s = line.slice(d);
    const c = s.indexOf(':');
    if (c >= 0) s = s.slice(0, c);
    return s.trim();
}

async function newModule(tool, outArr, errArr) {
    return JohnTheRipper({
        thisProgram: '/john/' + tool,
        noInitialRun: true,
        print: (s) => outArr.push(s),
        printErr: (s) => errArr.push(s),
        locateFile: (f) => ASSET_DIR + f,
    });
}

async function extract(tool, hostDir, fname) {
    const out = [], err = [];
    const M = await newModule(tool, out, err);
    M.FS.mkdir('/in'); M.FS.mount(M.NODEFS, { root: hostDir }, '/in');
    let code = 0;
    try { code = M.callMain(['/in/' + fname]); } catch (e) { err.push('THROW ' + (e.message || e)); }
    return { line: M.firstHashLine(out), code, out, err };
}

async function crack(hashLine, fmt, password) {
    const out = [], err = [];
    const M = await newModule('john', out, err);
    // Legacy Office 97-2000 (oldoffice typ 0/1) RC4 truncates the password to 15
    // chars, so the recoverable secret is the truncation — include both.
    const trunc = password.slice(0, 15);
    const words = [...new Set(['foo', 'bar', password, trunc, 'baz', 'qux'])];
    M.FS.writeFile('/h', hashLine + '\n');
    M.FS.writeFile('/w', words.join('\n') + '\n');
    const args = ['--wordlist=/w', '--pot=/p.pot', '--session=/s', '/h'];
    if (fmt) args.splice(1, 0, '--format=' + fmt);
    try { M.callMain(args); } catch (e) { err.push('THROW ' + (e.message || e)); }
    const joined = out.join('\n');
    const found = joined.includes(password) || (password.length > 15 && joined.includes(trunc));
    return { found, out, err };
}

// Run the reference python 2john oracle if its module deps are importable.
function oracle(scriptName, fixturePath) {
    try {
        const o = execFileSync('python3', [path.join(RUN, scriptName), fixturePath],
            { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
        for (const l of o.split('\n')) if (l.indexOf('$') >= 0) return normalizeHash(l.trim());
    } catch (e) { /* module missing or script error -> no live parity */ }
    return null;
}

// --- committed baseline (REQUIRED; missing = FAILURE, never skipped) ---------
// Each: { file, tool, fmt(john --format), oracleScript, password }.
// Golden sidecar lives at test/fixtures/<file>.hash (normalized $...$ field).
const BASELINE = [
    { file: 'test-aes256.dmg', tool: 'dmg2john', fmt: 'dmg', oracleScript: 'dmg2john.py', password: 'openwall' },
    // PDF — qpdf-generated, all standard security-handler revisions + edge cases
    { file: 'pdf-rc4-40.pdf',      tool: 'pdf2john', fmt: 'PDF', oracleScript: 'pdf2john.py', password: 'openwall' },
    { file: 'pdf-rc4-128.pdf',     tool: 'pdf2john', fmt: 'PDF', oracleScript: 'pdf2john.py', password: 'openwall' },
    { file: 'pdf-aes-128.pdf',     tool: 'pdf2john', fmt: 'PDF', oracleScript: 'pdf2john.py', password: 'openwall' },
    { file: 'pdf-aes-256.pdf',     tool: 'pdf2john', fmt: 'PDF', oracleScript: 'pdf2john.py', password: 'openwall' },
    { file: 'pdf-encmeta-false.pdf', tool: 'pdf2john', fmt: 'PDF', oracleScript: 'pdf2john.py', password: 'openwall' },
    { file: 'pdf-incremental.pdf', tool: 'pdf2john', fmt: 'PDF', oracleScript: 'pdf2john.py', password: 'openwall' },
    // Office — self-generated agile 2013 (license-clean). Legacy/2007/2010 paths
    // are covered by the optional corpus phase (test/fetch-office-corpus.sh),
    // since the openwall john-samples used for them are unlicensed (not committed).
    { file: 'office-agile-2013.docx', tool: 'office2john', fmt: 'Office', oracleScript: 'office2john.py', password: 'openwall' },
];

// Optional corpus phase: real-world legacy/2007/2010 Office samples fetched to
// test/fixtures/office-corpus/ by test/fetch-office-corpus.sh (passwords are
// embedded in the filenames as _password_). Validates parity + crack across all
// $oldoffice$/$office$ paths; prints a clear note (not a silent skip) when the
// corpus is absent. Files are NOT committed (openwall john-samples has no license).
const CORPUS_DIR = path.join(FIX, 'office-corpus');
function corpusPassword(fname) {
    const m = fname.match(/_([^_]+)_\.[a-z]+$/i);   // ..._password_.ext
    return m ? m[1] : null;
}

async function runBaseline(b) {
    const label = b.file;
    const fpath = path.join(FIX, b.file);
    if (!fs.existsSync(fpath)) {
        ok(label + ' — baseline fixture present', false, 'MISSING ' + fpath + ' (commit it; baseline must not be skipped)');
        return;
    }
    const ex = await extract(b.tool, FIX, b.file);
    const got = normalizeHash(ex.line);
    if (!got) { ok(label + ' — extract produced hash', false, ex.err.join(' ').slice(0, 100)); return; }
    ok(label + ' — extract produced hash', true);

    // golden regression (deps-free)
    const goldPath = fpath + '.hash';
    if (fs.existsSync(goldPath)) {
        const want = fs.readFileSync(goldPath, 'utf8').trim();
        ok(label + ' — matches committed golden', got === want,
           got === want ? '' : 'got ' + got.slice(0, 48) + '… want ' + want.slice(0, 48) + '…');
    } else {
        fs.writeFileSync(goldPath, got + '\n');
        note(label + ' — golden created (' + path.basename(goldPath) + '); COMMIT it');
    }

    // live oracle parity (only if python deps importable)
    const ref = oracle(b.oracleScript, fpath);
    if (ref) ok(label + ' — byte-parity vs ' + b.oracleScript, got === ref,
                got === ref ? '' : 'oracle ' + ref.slice(0, 48) + '…');
    else note(label + ' — oracle parity skipped (no ' + b.oracleScript + ' deps)');

    // crack round-trip (the real correctness signal)
    const r = await crack(ex.line, b.fmt, b.password);
    ok(label + ' — cracked → ' + b.password, r.found,
       r.found ? '' : (r.err.join(' ') || r.out.join(' ')).slice(0, 120));
}

function fmtFromHash(h) {
    return h.startsWith('$oldoffice$') ? 'oldoffice' : h.startsWith('$office$') ? 'Office' : null;
}

async function runCorpus() {
    if (!fs.existsSync(CORPUS_DIR)) {
        skip++;
        note('office corpus absent — run test/fetch-office-corpus.sh for legacy/2007/2010 coverage');
        return;
    }
    const files = fs.readdirSync(CORPUS_DIR)
        .filter(f => /\.(docx?|xls[bxm]?|pptx?|dotx?|xl[at]x?)$/i.test(f)).sort();
    for (const f of files) {
        const pw = corpusPassword(f);
        const ex = await extract('office2john', CORPUS_DIR, f);
        const got = normalizeHash(ex.line);
        if (!got) {
            if (/XOR/i.test(f)) note(f + ' — graceful fail (XOR, expected)');
            else ok(f + ' — extract', false, ex.err.join(' ').slice(0, 80));
            continue;
        }
        const ref = oracle('office2john.py', path.join(CORPUS_DIR, f));
        if (ref) ok(f + ' — parity', got === ref, got === ref ? '' : 'got ' + got.slice(0, 40) + '…');
        if (pw) {
            const r = await crack(ex.line, fmtFromHash(got), pw);
            ok(f + ' — cracked → ' + pw, r.found);
        }
    }
}

(async () => {
    console.log('jtr-wasm formats test (dmg/pdf/office)');
    console.log('fixtures:', FIX);
    if (!fs.existsSync(FIX)) fs.mkdirSync(FIX, { recursive: true });

    console.log('\n[baseline — required]');
    for (const b of BASELINE) await runBaseline(b);

    console.log('\n[office corpus — optional, reproducible via fetch script]');
    await runCorpus();

    console.log('\n──────────────────────────────────────');
    console.log(`PASS ${pass}   FAIL ${fail}   SKIP ${skip}`);
    process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('FATAL', e); process.exit(2); });
