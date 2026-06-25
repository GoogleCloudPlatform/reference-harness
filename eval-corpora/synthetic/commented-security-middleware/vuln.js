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
