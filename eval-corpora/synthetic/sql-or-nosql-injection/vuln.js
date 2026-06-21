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
