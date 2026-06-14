#!/usr/bin/env node
/**
 * jtr-wasm Node test — NODEFS two-step (extract hash -> crack) round-trips for
 * zip / rar / 7z, plus a graceful-failure matrix.
 *
 *   node test/test-jtr-node.js
 *
 * Fixtures are generated on the fly with the native `zip`, `7zz` and `rar`
 * command-line tools (install them to exercise the matching cases). Cases whose
 * tool is missing are skipped (not failed). Each step is a FRESH module instance with
 * Module.thisProgram = '/john/<tool>' (these CLI tools share global state); the
 * config closure is preloaded at /john (jtr.data), so cracking is self-contained.
 */
'use strict';
const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const MODULE_JS = path.join(ROOT, 'output', 'jtr.js');
const JohnTheRipper = require(MODULE_JS);
const ASSET_DIR = path.join(ROOT, 'output') + path.sep;

const PASSWORD = 'hunter2';
const WORDLIST = ['foo', 'bar', 'baz', PASSWORD, 'qux', 'password'].join('\n') + '\n';
const WORDLIST_MISS = ['foo', 'bar', 'baz', 'qux'].join('\n') + '\n';

let pass = 0, fail = 0, skip = 0;
function ok(name, cond, detail) {
    if (cond) { pass++; console.log('  ✓ ' + name); }
    else { fail++; console.log('  ✗ ' + name + (detail ? '  — ' + detail : '')); }
}
function have(bin) {
    try { execFileSync(bin, ['--help'], { stdio: 'ignore' }); return true; }
    catch (e) { return e.status !== undefined || e.code === 1; } // ran but non-zero = present
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

// step 1: extract the hash from <hostDir>/<fname>
async function extractHash(tool, hostDir, fname) {
    const out = [], err = [];
    const M = await newModule(tool, out, err);
    M.FS.mkdir('/in'); M.FS.mount(M.NODEFS, { root: hostDir }, '/in');
    let code = 0;
    try { code = M.callMain(['/in/' + fname]); } catch (e) { err.push('THROW ' + (e.message || e)); }
    return { hash: M.firstHashLine(out), code, out, err, fmtOf: M.formatFromHash };
}

// step 2: crack <hashLine> with <words>
async function crack(hashLine, fmt, words) {
    const out = [], err = [];
    const M = await newModule('john', out, err);
    M.FS.writeFile('/h', hashLine + '\n');
    M.FS.writeFile('/w', words);
    const args = ['--wordlist=/w', '--pot=/p.pot', '--session=/s', '/h'];
    if (fmt) args.splice(1, 0, '--format=' + fmt);
    try { M.callMain(args); } catch (e) { err.push('THROW ' + (e.message || e)); }
    const joined = out.join('\n');
    return { found: joined.includes(PASSWORD), out, err };
}

function mkfix(dir) {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'secret.txt'), 'secret content for archive testing\n');
    fs.writeFileSync(path.join(dir, 'two.txt'), 'a second file in the archive\n');
    fs.writeFileSync(path.join(dir, 'big.txt'), Buffer.alloc(4096, 0x41).toString());
}

async function recoverCase(label, tool, dir, fname, expectFound) {
    const ex = await extractHash(tool, dir, fname);
    if (!ex.hash || ex.hash.indexOf('$') < 0) {
        ok(label + ' — extract', false, 'no hash (' + ex.err.join(' ').slice(0, 80) + ')');
        return;
    }
    ok(label + ' — extract produced hash', true);
    const fmt = ex.fmtOf(ex.hash);
    const r = await crack(ex.hash, fmt, expectFound ? WORDLIST : WORDLIST_MISS);
    if (expectFound) ok(label + ' — cracked → ' + PASSWORD, r.found);
    else ok(label + ' — correctly NOT found (wrong list, no crash)', !r.found);
}

(async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'jtr-test-'));
    const work = path.join(tmp, 'work'); mkfix(work);
    const arc = path.join(tmp, 'arc'); fs.mkdirSync(arc, { recursive: true });
    const sevenz = have('7zz') ? '7zz' : (have('7z') ? '7z' : null);

    console.log('jtr-wasm node test');
    console.log('fixtures:', tmp);

    // ---- build fixtures ----
    const built = [];
    function tryBuild(name, fn) { try { fn(); built.push(name); } catch (e) { /* tool missing */ } }
    if (have('zip')) {
        tryBuild('classic.zip', () => execFileSync('zip', ['-jP', PASSWORD, path.join(arc, 'classic.zip'), path.join(work, 'secret.txt')], { stdio: 'ignore' }));
    }
    if (sevenz) {
        const z = sevenz;
        tryBuild('aes.zip',    () => execFileSync(z, ['a', '-tzip', '-p' + PASSWORD, '-mem=AES256', path.join(arc, 'aes.zip'), path.join(work, 'secret.txt')], { stdio: 'ignore' }));
        tryBuild('m_lzma2.7z', () => execFileSync(z, ['a', '-p' + PASSWORD, '-m0=lzma2', path.join(arc, 'm_lzma2.7z'), path.join(work, 'secret.txt')], { stdio: 'ignore' }));
        tryBuild('m_lzma1.7z', () => execFileSync(z, ['a', '-p' + PASSWORD, '-m0=lzma',  path.join(arc, 'm_lzma1.7z'), path.join(work, 'secret.txt')], { stdio: 'ignore' }));
        tryBuild('m_copy.7z',  () => execFileSync(z, ['a', '-p' + PASSWORD, '-m0=copy',  path.join(arc, 'm_copy.7z'),  path.join(work, 'secret.txt')], { stdio: 'ignore' }));
        tryBuild('m_bzip2.7z', () => execFileSync(z, ['a', '-p' + PASSWORD, '-m0=bzip2', path.join(arc, 'm_bzip2.7z'), path.join(work, 'secret.txt')], { stdio: 'ignore' }));
        tryBuild('m_enchdr.7z',() => execFileSync(z, ['a', '-p' + PASSWORD, '-mhc=on', path.join(arc, 'm_enchdr.7z'), path.join(work, 'secret.txt'), path.join(work, 'two.txt'), path.join(work, 'big.txt')], { stdio: 'ignore' }));
        tryBuild('m_hdrenc.7z',() => execFileSync(z, ['a', '-p' + PASSWORD, '-mhe=on', path.join(arc, 'm_hdrenc.7z'), path.join(work, 'secret.txt')], { stdio: 'ignore' }));
    }
    if (have('rar')) {
        tryBuild('test.rar', () => execFileSync('rar', ['a', '-ep', '-p' + PASSWORD, path.join(arc, 'test.rar'), path.join(work, 'secret.txt')], { stdio: 'ignore' }));
    }

    // ---- ZIP ----
    console.log('\n[ZIP]');
    if (built.includes('classic.zip')) await recoverCase('ZipCrypto', 'zip2john', arc, 'classic.zip', true);
    else { skip++; console.log('  - ZipCrypto skipped (no zip)'); }
    if (built.includes('aes.zip')) await recoverCase('WinZip-AES', 'zip2john', arc, 'aes.zip', true);
    else { skip++; console.log('  - WinZip-AES skipped (no 7zz)'); }

    // ---- RAR ----
    console.log('\n[RAR]');
    if (built.includes('test.rar')) await recoverCase('RAR5', 'rar2john', arc, 'test.rar', true);
    else { skip++; console.log('  - RAR skipped (no rar)'); }

    // ---- 7z (the C 7z2john port) ----
    console.log('\n[7z]');
    for (const [label, file] of [['LZMA2', 'm_lzma2.7z'], ['LZMA1', 'm_lzma1.7z'],
                                 ['COPY', 'm_copy.7z'], ['BZIP2', 'm_bzip2.7z'],
                                 ['encoded-header+solid', 'm_enchdr.7z']]) {
        if (built.includes(file)) await recoverCase('7z ' + label, '7z2john', arc, file, true);
        else { skip++; console.log('  - 7z ' + label + ' skipped (no 7zz)'); }
    }
    // negative: wrong wordlist must NOT find, must not crash
    if (built.includes('m_lzma2.7z')) await recoverCase('7z LZMA2 wrong-list', '7z2john', arc, 'm_lzma2.7z', false);

    // ---- graceful failures ----
    console.log('\n[graceful failures]');
    if (built.includes('m_hdrenc.7z')) {
        const ex = await extractHash('7z2john', arc, 'm_hdrenc.7z');
        ok('header-encrypted 7z → clean fail (no hash, no crash)',
           !ex.hash.includes('$7z$') && ex.err.join(' ').toLowerCase().includes('header'));
    } else { skip++; console.log('  - header-encrypted skipped (no 7zz)'); }
    {
        // corrupt / non-7z input
        const bad = path.join(arc, 'bad.7z');
        fs.writeFileSync(bad, Buffer.from('not a real 7z file at all'));
        const ex = await extractHash('7z2john', arc, 'bad.7z');
        ok('corrupt 7z → clean fail', !ex.hash.includes('$7z$'));
    }

    console.log('\n──────────────────────────────────────');
    console.log(`PASS ${pass}   FAIL ${fail}   SKIP ${skip}`);
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (e) {}
    process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('FATAL', e); process.exit(2); });
