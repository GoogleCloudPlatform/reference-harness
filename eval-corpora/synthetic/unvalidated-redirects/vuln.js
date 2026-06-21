// Synthetic eval target for the `unvalidated-redirects` detection skill.
// Vulnerability: req.query.url passed to res.redirect with no allowlist or
// origin check — attacker can craft a phishing link that looks like ours
// then redirects to an attacker-controlled host.
// Expected detection: gemini.unvalidated-redirect.

const express = require('express');
const app = express();

app.get('/redirect', (req, res) => {
  // BUG: redirect target attacker-controlled
  res.redirect(req.query.url);
});

app.get('/login/callback', (req, res) => {
  // BUG: same pattern via 'next' param (common login-callback flaw)
  res.redirect(req.query.next || '/');
});

module.exports = app;
