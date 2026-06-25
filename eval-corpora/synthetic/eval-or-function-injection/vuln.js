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
