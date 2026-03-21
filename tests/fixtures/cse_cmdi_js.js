/**
 * CWE-78: OS Command Injection in JavaScript/Node.js
 * User input passed to child_process exec without sanitization.
 */

const { exec, execSync } = require("child_process");
const http = require("http");
const url = require("url");

function pingHost(host, callback) {
  // Command injection via exec
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    callback(err, stdout);
  });
}

function getFileType(filename) {
  // Command injection via execSync
  return execSync(`file ${filename}`).toString();
}

function lookupDns(domain) {
  // Command injection via exec with template literal
  return new Promise((resolve, reject) => {
    exec(`dig +short ${domain}`, (err, stdout) => {
      if (err) reject(err);
      else resolve(stdout.trim());
    });
  });
}

function convertImage(inputPath, outputPath) {
  // Command injection via both parameters
  execSync(`convert ${inputPath} ${outputPath}`);
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  if (parsed.pathname === "/ping") {
    const host = parsed.query.host || "localhost";
    pingHost(host, (err, result) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(result || err.message);
    });
  }
});

if (require.main === module) {
  server.listen(3001, () => console.log("Listening on :3001"));
}

module.exports = { pingHost, getFileType, lookupDns, convertImage };
