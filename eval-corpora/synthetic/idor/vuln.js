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

// Synthetic eval target for the `idor` detection skill.
// Vulnerability: route reads userId from URL params and queries the DB by it
// without verifying the authenticated user (req.session.userId) matches.
// Expected detection: gemini.idor at this file.

const express = require('express');
const app = express();

function isLoggedIn(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.sendStatus(401);
}

app.get('/users/:userId/allocations', isLoggedIn, (req, res) => {
  // BUG: trusting the URL :userId instead of req.session.userId
  db.allocations.find({userId: req.params.userId}, (err, docs) => {
    if (err) return res.sendStatus(500);
    res.json(docs);
  });
});

module.exports = app;
