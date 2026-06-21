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
