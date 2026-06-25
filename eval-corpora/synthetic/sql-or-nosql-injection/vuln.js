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

// Synthetic eval target for the `sql-or-nosql-injection` detection skill.
// Vulnerability: req.body.threshold interpolated into a MongoDB $where
// clause as a string — attacker can inject arbitrary JS into the query,
// equivalent to NoSQL injection. (NodeGoat's canonical pattern.)
// Expected detection: gemini.nosql-injection / mongo-where-injection.

const express = require('express');
const app = express();
app.use(express.json());

app.post('/items/search', (req, res) => {
  // BUG: user input concatenated into a $where JS expression
  const threshold = req.body.threshold;
  db.items.find({$where: `this.price > ${threshold}`}, (err, docs) => {
    if (err) return res.sendStatus(500);
    res.json(docs);
  });
});

module.exports = app;
