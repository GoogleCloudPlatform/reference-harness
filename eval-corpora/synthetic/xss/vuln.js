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
