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

// Synthetic eval target for the `xss` detection skill.
// Vulnerability: Swig template engine globally configured with autoescape:
// false, then user input (req.query.name) is rendered into a template.
// Any string containing <script> will execute in victims' browsers.
// Expected detection: gemini.xss-autoescape-disabled (or per-route xss).

const express = require('express');
const swig = require('swig-templates');
const app = express();

// BUG: autoescape disabled globally
swig.setDefaults({autoescape: false});
app.engine('html', swig.renderFile);
app.set('view engine', 'html');

app.get('/greet', (req, res) => {
  // Unsanitized user input rendered into HTML
  res.render('greeting.html', {name: req.query.name});
});

module.exports = app;
