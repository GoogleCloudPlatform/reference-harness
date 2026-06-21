// Synthetic eval target for the `eval-or-function-injection` detection skill.
// Vulnerability: req.body.expression passed directly to eval() — attacker
// achieves arbitrary server-side JavaScript execution (RCE).
// Expected detection: gemini.server-side-js-injection on this route.

const express = require('express');
const app = express();
app.use(express.json());

app.post('/calculate', (req, res) => {
  // BUG: eval on unvalidated request body
  const result = eval(req.body.expression);
  res.json({result});
});

module.exports = app;
