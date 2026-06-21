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
