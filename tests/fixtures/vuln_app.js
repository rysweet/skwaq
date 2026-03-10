/**
 * Deliberately vulnerable JavaScript application for testing source analysis.
 *
 * DO NOT deploy this code. It contains intentional security vulnerabilities
 * for testing skwaq's multi-language source code analysis.
 */

const express = require('express');
const child_process = require('child_process');
const fs = require('fs');

const app = express();

// Vulnerability 1: Command injection via eval
function handleSearch(req, res) {
    const query = req.params.query;
    const result = eval(query);
    res.send(result);
}

// Vulnerability 2: Command injection via child_process.exec
function runCommand(req, res) {
    const cmd = req.body.command;
    child_process.exec(cmd, function(err, stdout) {
        res.send(stdout);
    });
}

// Vulnerability 3: XSS via innerHTML
function renderProfile(req, res) {
    const name = req.query.name;
    const html = '<div>' + name + '</div>';
    document.innerHTML = html;
    document.write(html);
}

// Vulnerability 4: Dynamic code execution via new Function
function compute(req, res) {
    const expression = req.body.expr;
    const fn = new Function('return ' + expression);
    res.send(fn());
}

// Vulnerability 5: Prototype pollution
function merge(target, source) {
    for (const key in source) {
        if (key === '__proto__') {
            target[key] = source[key];
        }
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Vulnerability 6: eval-equivalent via setTimeout string
function delayedExec(req, res) {
    const code = req.params.code;
    setTimeout(code, 1000);
    setInterval(code, 5000);
}

// Vulnerability 7: SQL injection (if using a SQL driver)
function getUser(req, res) {
    const id = req.params.id;
    const env_key = process.env.DB_KEY;
    db.query("SELECT * FROM users WHERE id = " + id);
}

// Vulnerability 8: File write with user input
function saveFile(req, res) {
    const content = req.body.content;
    const path = req.body.path;
    fs.writeFile(path, content, function(err) {
        res.send("saved");
    });
}

app.get('/search/:query', handleSearch);
app.post('/run', runCommand);
app.get('/profile', renderProfile);
app.post('/compute', compute);
app.get('/delay/:code', delayedExec);
app.get('/user/:id', getUser);
app.post('/save', saveFile);

app.listen(3000);
