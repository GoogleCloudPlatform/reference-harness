// Synthetic eval target for the `hardcoded-secrets` detection skill.
// Vulnerability: API keys and session secrets hardcoded as string literals
// committed to source — visible to anyone with repo read access, can't be
// rotated without a code change.
// Expected detection: gemini.hardcoded-secret (likely multiple findings).

const express = require('express');
const session = require('express-session');
const app = express();

// BUG: secrets in source
// (placeholder values shaped like real credentials so the detection skill
// fires, but deliberately NOT matching secret-scanner regexes — the original
// Stripe test-key shape `sk_live_*` was blocked by GitHub Push Protection
// even though it was Stripe's own public documentation example value.)
const STRIPE_API_KEY = 'demo_stripe_key_PLACEHOLDER_replace_for_prod_use';
const SESSION_SECRET = 'demo_session_secret_PLACEHOLDER_replace_for_prod';
const JWT_SIGNING_KEY = 'demo_jwt_signing_key_PLACEHOLDER_replace_for_prod';

app.use(session({secret: SESSION_SECRET, resave: false, saveUninitialized: false}));

app.post('/charge', (req, res) => {
  chargeCustomer(STRIPE_API_KEY, req.body.amount);
  res.send('charged');
});

module.exports = app;
