// Universal NODEFS contract test.
// Usage: node test-nodefs-contract.js <path-to-module.js> [fixture-dir]
// Verifies FS, WORKERFS, NODEFS are all live objects, and that NODEFS
// can mount a real host directory.

const path = require('path');
const fs = require('fs');

const modulePath = process.argv[2];
const fixtureDir = process.argv[3] || path.resolve(__dirname);

if (!modulePath) {
    console.error('usage: node test-nodefs-contract.js <module.js> [fixture-dir]');
    process.exit(2);
}
if (!fs.existsSync(modulePath)) {
    console.error('FAIL: module not found:', modulePath);
    process.exit(1);
}

const absModule = path.resolve(modulePath);
const loader = require(absModule);

(async () => {
    const M = await loader({ print: () => {}, printErr: () => {} });
    const checks = [
        ['FS',       typeof M.FS],
        ['WORKERFS', typeof M.WORKERFS],
        ['NODEFS',   typeof M.NODEFS],
    ];
    for (const [name, t] of checks) {
        if (t !== 'object') {
            console.error(`FAIL: Module.${name} is ${t} (expected object)`);
            if (t === 'string') console.error(`   value: ${M[name]}`);
            process.exit(1);
        }
    }

    // Use a unique mount point to avoid colliding with any pre-existing
    // pre.js/preRun mounts a module might set up.
    const MP = '/nodefs-contract-test';
    try {
        M.FS.mkdir(MP);
    } catch (e) { /* already exists */ }
    M.FS.mount(M.NODEFS, { root: fixtureDir }, MP);

    const entries = M.FS.readdir(MP).filter(n => n !== '.' && n !== '..');
    if (entries.length === 0) {
        console.error('FAIL: NODEFS readdir returned empty for', fixtureDir);
        process.exit(1);
    }

    let stat;
    for (const name of entries) {
        try {
            const s = M.FS.stat(MP + '/' + name);
            if (s && s.size >= 0) { stat = { name, size: s.size }; break; }
        } catch (e) { /* keep trying */ }
    }
    if (!stat) {
        console.error('FAIL: could not stat any entry in', fixtureDir);
        process.exit(1);
    }

    const label = path.basename(path.dirname(absModule)) + '/' + path.basename(absModule);
    console.log('OK:', label, '— FS/WORKERFS/NODEFS all live; NODEFS read', stat.name, `(${stat.size}B)`);
})().catch(e => {
    console.error('FAIL:', e && e.message || e);
    if (e && e.stack) console.error(e.stack);
    process.exit(1);
});
