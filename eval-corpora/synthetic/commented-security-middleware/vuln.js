// Synthetic eval target for the `commented-security-middleware` skill.
// Vulnerability: helmet (security headers) and csurf (CSRF protection)
// are imported but the registration calls are entirely commented out.
// Net effect: the app runs without security headers OR CSRF protection.
// Expected detection: gemini.security-middleware-commented (or csrf-disabled
// / security-headers-disabled).

const express = require('express');
// const helmet = require("helmet");
// const csrf = require("csurf");
const app = express();

app.use(express.urlencoded({extended: true}));

// BUG: security middleware never registered
// app.use(helmet());
// app.use(csrf());

app.post('/transfer', (req, res) => {
  transfer(req.body.from, req.body.to, req.body.amount);
  res.send('transferred');
});

module.exports = app;
