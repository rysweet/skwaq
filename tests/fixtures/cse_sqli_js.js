/**
 * CWE-89: SQL Injection in JavaScript/Node.js
 * Constructs SQL queries from user input via string concatenation.
 */

const http = require("http");
const url = require("url");

// Simulated database query function
function query(sql) {
  console.log("Executing:", sql);
  return [];
}

function findUser(username) {
  // SQL injection via template literal
  return query(`SELECT * FROM users WHERE username = '${username}'`);
}

function searchProducts(category, sortBy) {
  // SQL injection in both WHERE and ORDER BY
  const sql = "SELECT * FROM products WHERE category = '" + category + "' ORDER BY " + sortBy;
  return query(sql);
}

function deleteRecord(table, id) {
  // SQL injection via table name and id
  return query(`DELETE FROM ${table} WHERE id = ${id}`);
}

function authenticate(user, pass) {
  // Classic login bypass
  return query(
    "SELECT id FROM users WHERE name='" + user + "' AND password='" + pass + "'"
  );
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  if (parsed.pathname === "/user") {
    const result = findUser(parsed.query.name || "");
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(result));
  }
});

if (require.main === module) {
  server.listen(3003, () => console.log("Listening on :3003"));
}

module.exports = { findUser, searchProducts, deleteRecord, authenticate };
