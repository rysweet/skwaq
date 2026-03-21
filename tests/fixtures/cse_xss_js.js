/**
 * CWE-79: Cross-Site Scripting (XSS) in JavaScript
 * User input inserted into DOM without sanitization.
 */

const http = require("http");
const url = require("url");

function renderSearchPage(query) {
  // Reflected XSS: user input directly in HTML
  return `
    <html>
    <body>
      <h1>Search Results</h1>
      <p>You searched for: ${query}</p>
      <form action="/search">
        <input name="q" value="${query}" />
        <button type="submit">Search</button>
      </form>
    </body>
    </html>`;
}

function renderUserProfile(username, bio) {
  // Stored XSS: user-controlled bio in HTML
  return `<div class="profile">
    <h2>${username}</h2>
    <div class="bio">${bio}</div>
  </div>`;
}

function renderError(message) {
  // Reflected XSS via error message
  return `<html><body><h1>Error</h1><p>${message}</p></body></html>`;
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  if (parsed.pathname === "/search") {
    const query = parsed.query.q || "";
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(renderSearchPage(query));
  } else {
    res.writeHead(404, { "Content-Type": "text/html" });
    res.end(renderError(`Page ${parsed.pathname} not found`));
  }
});

if (require.main === module) {
  server.listen(3000, () => console.log("Listening on :3000"));
}

module.exports = { renderSearchPage, renderUserProfile, renderError };
