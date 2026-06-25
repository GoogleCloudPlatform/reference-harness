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

// Synthetic eval target for the `broken-authorization` detection skill.
// Vulnerability: an admin-only route (delete any user) is protected only
// by isLoggedIn — there's no isAdmin role check. Any authenticated user
// can delete any other user's account.
// Expected detection: gemini.broken-authz / missing-authz.

const express = require('express');
const app = express();

function isLoggedIn(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.sendStatus(401);
}

function isAdmin(req, res, next) {
  if (req.session && req.session.role === 'admin') return next();
  res.sendStatus(403);
}

// BUG: admin operation guarded only by isLoggedIn, not isAdmin
// Any authenticated (non-admin) user can hit this and delete anyone.
app.post('/admin/users/:id/delete', isLoggedIn, (req, res) => {
  db.users.deleteOne({_id: req.params.id});
  res.send('deleted');
});

// Counter-example for context (NOT the bug we're testing):
app.post('/admin/users/:id/promote', isLoggedIn, isAdmin, (req, res) => {
  db.users.updateOne({_id: req.params.id}, {$set: {role: 'admin'}});
  res.send('promoted');
});

module.exports = app;
