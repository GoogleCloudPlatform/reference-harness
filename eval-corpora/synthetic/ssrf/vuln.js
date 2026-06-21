// Synthetic eval target for the `ssrf` detection skill.
// Vulnerability: user-controlled URL passed to an outbound HTTP client
// (needle.get) with no allowlist or host validation. Attacker can pivot
// to internal services.
// Expected detection: gemini.ssrf on this route.

const express = require('express');
const needle = require('needle');
const app = express();

app.get('/fetch', (req, res) => {
  // BUG: req.query.url is attacker-controlled, no allowlist
  needle.get(req.query.url, (err, response) => {
    if (err) return res.sendStatus(502);
    res.send(response.body);
  });
});

module.exports = app;
