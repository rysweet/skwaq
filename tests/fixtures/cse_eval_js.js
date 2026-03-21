/**
 * CWE-94: Improper Control of Generation of Code (eval injection)
 * Uses eval/Function constructor with user-controlled input.
 */

const http = require("http");
const url = require("url");
const vm = require("vm");

function calculate(expression) {
  // Code injection via eval
  return eval(expression);
}

function processTemplate(template, data) {
  // Code injection via Function constructor
  const fn = new Function("data", `return \`${template}\`;`);
  return fn(data);
}

function runUserScript(code) {
  // Code injection: vm.runInThisContext shares global scope
  return vm.runInThisContext(code);
}

function dynamicSort(items, sortExpr) {
  // Code injection via eval in sort comparator
  return items.sort((a, b) => eval(sortExpr));
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  if (parsed.pathname === "/calc") {
    try {
      const result = calculate(parsed.query.expr || "0");
      res.end(String(result));
    } catch (e) {
      res.writeHead(500);
      res.end(e.message);
    }
  }
});

if (require.main === module) {
  server.listen(3004, () => console.log("Listening on :3004"));
}

module.exports = { calculate, processTemplate, runUserScript, dynamicSort };
