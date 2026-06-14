/* Minimal server for the jtr-wasm browser test.
 * Generates encrypted fixtures with native zip/7zz/rar, serves them plus the
 * built module (output/jtr.*) and the harness, with COOP/COEP headers.
 *   node test/browser/serve.js [port]
 */
const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { execFileSync } = require("child_process");

const PORT = parseInt(process.argv[2] || "8097", 10);
const ROOT = path.resolve(__dirname, "..", "..");          // jtr-wasm/
const OUT = path.join(ROOT, "output");
const HERE = __dirname;
const PASSWORD = "hunter2";

// --- generate fixtures ---
const fixDir = fs.mkdtempSync(path.join(os.tmpdir(), "jtr-bfix-"));
const work = path.join(fixDir, "w"); fs.mkdirSync(work);
fs.writeFileSync(path.join(work, "secret.txt"), "secret content for archive testing\n");
function sevenz() { for (const b of ["7zz","7z"]) { try { execFileSync(b,["i"],{stdio:"ignore"}); return b; } catch(e){ if(e.code!=="ENOENT") return b; } } return null; }
const z = sevenz();
try { execFileSync(z, ["a","-tzip","-p"+PASSWORD,"-mem=AES256", path.join(fixDir,"aes.zip"), path.join(work,"secret.txt")], {stdio:"ignore"}); } catch(e){}
try { execFileSync(z, ["a","-p"+PASSWORD,"-m0=lzma2", path.join(fixDir,"m_lzma2.7z"), path.join(work,"secret.txt")], {stdio:"ignore"}); } catch(e){}
try { execFileSync("rar", ["a","-ep","-p"+PASSWORD, path.join(fixDir,"test.rar"), path.join(work,"secret.txt")], {stdio:"ignore"}); } catch(e){}

const MIME = { ".js":"text/javascript", ".wasm":"application/wasm", ".data":"application/octet-stream",
  ".html":"text/html", ".zip":"application/zip", ".7z":"application/x-7z-compressed", ".rar":"application/vnd.rar" };

function serveFile(res, file) {
  if (!fs.existsSync(file)) { res.writeHead(404); res.end("not found: " + file); return; }
  res.writeHead(200, {
    "Content-Type": MIME[path.extname(file)] || "application/octet-stream",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
  });
  fs.createReadStream(file).pipe(res);
}

http.createServer((req, res) => {
  const url = req.url.split("?")[0];
  if (url === "/" || url === "/index.html") return serveFile(res, path.join(HERE, "index.html"));
  if (url === "/jtr-worker.js") return serveFile(res, path.join(HERE, "jtr-worker.js"));
  if (url === "/jtr.js" || url === "/jtr.wasm" || url === "/jtr.data") return serveFile(res, path.join(OUT, url.slice(1)));
  if (url.startsWith("/fixtures/")) return serveFile(res, path.join(fixDir, url.slice("/fixtures/".length)));
  res.writeHead(404); res.end("404");
}).listen(PORT, () => console.log("jtr browser test on http://localhost:" + PORT + "  fixtures:" + fixDir));
