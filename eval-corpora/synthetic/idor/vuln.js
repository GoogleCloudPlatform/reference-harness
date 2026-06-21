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
