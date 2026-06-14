/* Plain-JS mirror of jtr-recover-worker.ts for the standalone browser test.
   Exercises the real browser WORKERFS two-step (FileReaderSync path). */
importScripts("/jtr.js");
const ASSET_DIR = "/";

function newInstance(tool, print, printErr) {
  return JohnTheRipper({
    thisProgram: "/john/" + tool,
    noInitialRun: true,
    locateFile: (f) => ASSET_DIR + f,
    print: print || (() => {}),
    printErr: printErr || (() => {}),
  });
}

async function recover(archiveFile, wordlistText) {
  // step 1: extract hash
  const out1 = [], err1 = [];
  const probe = await newInstance("john");
  const tool = probe.detectTool(archiveFile.name);
  const ex = await newInstance(tool, (s) => out1.push(s), (s) => err1.push(s));
  const apath = ex.mountArchive(archiveFile, "/in");
  try { ex.callMain([apath]); } catch (e) { err1.push("THROW " + (e.message || e)); }
  const hash = ex.firstHashLine(out1);
  if (!hash || hash.indexOf("$") < 0) {
    return { found: false, error: "no hash: " + err1.join(" ").slice(0, 160) };
  }

  // step 2: crack with an in-memory wordlist (MEMFS write — small list)
  const out2 = [];
  const total = wordlistText.split("\n").filter((l) => l.length).length;
  const jn = await newInstance("john", (s) => out2.push(s), () => {});
  jn.onCrackProgress = (tried) => {
    self.postMessage({ name: archiveFile.name, progress: true, tried, total,
      percent: total ? Math.min(99.9, (tried / total) * 100) : 0 });
  };
  jn.FS.writeFile("/hash.txt", hash + "\n");
  jn.FS.writeFile("/words.txt", wordlistText);
  const fmt = jn.formatFromHash(hash);
  const args = ["--wordlist=/words.txt", "--pot=/p.pot", "--session=/s", "/hash.txt"];
  if (fmt) args.splice(1, 0, "--format=" + fmt);
  try { jn.callMain(args); } catch (e) { out2.push("THROW " + (e.message || e)); }
  for (const line of out2) {
    const clean = line.replace(/\x1b\[[0-9;]*m/g, "");   // strip john's ANSI color
    const m = clean.match(/^(\S.*?)\s{2,}\(.*\)\s*$/);
    if (m) return { found: true, password: m[1], format: fmt, hash: hash.slice(0, 50) };
  }
  return { found: false, format: fmt, hash: hash.slice(0, 50) };
}

self.onmessage = async (e) => {
  try {
    const r = await recover(e.data.archiveFile, e.data.wordlist);
    self.postMessage({ name: e.data.name, ...r });
  } catch (err) {
    self.postMessage({ name: e.data.name, found: false, error: String(err && err.message || err) });
  }
};
