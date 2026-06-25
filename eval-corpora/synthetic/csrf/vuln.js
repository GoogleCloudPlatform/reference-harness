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
