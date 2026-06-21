// Synthetic eval target for the `csrf` detection skill.
// Vulnerability: state-changing POST route with NO csurf-style middleware
// registered and no CSRF token validation. The app stack never invokes
// csurf, helmet, or any equivalent protection.
// Expected detection: gemini.csrf-disabled (or equivalent) on this route.

const express = require('express');
const session = require('express-session');
const app = express();

app.use(express.urlencoded({extended: true}));
app.use(session({secret: 'demo', resave: false, saveUninitialized: false}));

// BUG: no app.use(csrf()) — state-changing route accepts cross-origin POSTs
app.post('/profile/update', (req, res) => {
  saveProfile(req.session.userId, req.body);
  res.send('profile updated');
});

module.exports = app;
