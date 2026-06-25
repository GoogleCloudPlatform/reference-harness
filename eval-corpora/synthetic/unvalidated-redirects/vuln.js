// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
