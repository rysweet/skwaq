/**
 * CWE-22: Path Traversal in JavaScript/Node.js
 * Serves files based on user-controlled path without validation.
 */

const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");

const STATIC_DIR = "/var/www/static";
const UPLOAD_DIR = "/var/www/uploads";

function serveFile(filename, res) {
  // Path traversal: no validation of ".." sequences
  const filePath = path.join(STATIC_DIR, filename);
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end("Not found");
    } else {
      res.writeHead(200);
      res.end(data);
    }
  });
}

function getUpload(userId, filename) {
  // Path traversal via both userId and filename
  const filePath = `${UPLOAD_DIR}/${userId}/${filename}`;
  return fs.readFileSync(filePath);
}

function readConfig(name) {
  // Path traversal: string concatenation
  return fs.readFileSync("/etc/app/configs/" + name + ".json", "utf8");
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  if (parsed.pathname === "/file") {
    const name = parsed.query.name || "index.html";
    serveFile(name, res);
  } else if (parsed.pathname === "/config") {
    try {
      const config = readConfig(parsed.query.name);
      res.end(config);
    } catch (e) {
      res.writeHead(500);
      res.end(e.message);
    }
  }
});

if (require.main === module) {
  server.listen(3002, () => console.log("Listening on :3002"));
}

module.exports = { serveFile, getUpload, readConfig };
