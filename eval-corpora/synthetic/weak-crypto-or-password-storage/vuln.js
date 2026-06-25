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

// Synthetic eval target for the `weak-crypto-or-password-storage` skill.
// Vulnerability: passwords hashed with MD5, no salt. MD5 is broken for
// password storage (fast + collision-prone); missing salt enables rainbow
// table attacks.
// Expected detection: gemini.weak-password-storage / weak-crypto.

const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json());

app.post('/register', (req, res) => {
  // BUG: MD5 + no salt for password storage
  const hash = crypto.createHash('md5').update(req.body.password).digest('hex');
  db.users.insertOne({username: req.body.username, password: hash}, (err) => {
    if (err) return res.sendStatus(500);
    res.send('registered');
  });
});

module.exports = app;
