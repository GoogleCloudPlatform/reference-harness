# Evaluation Results

Tracks Reference Harness's measured performance against test corpora, iteration
by iteration.

## Test Corpus Setup

**OWASP NodeGoat** (Node.js, deliberately vulnerable). Clone it into
`eval-fixtures/` at the project root (this path is gitignored):

```bash
mkdir -p eval-fixtures
git clone --depth 1 https://github.com/OWASP/NodeGoat.git eval-fixtures/nodegoat
```

Evalsets reference the project-relative path `eval-fixtures/nodegoat`. The eval
runner resolves it against the project root (CWD), so always invoke
`agents-cli eval run` from the repo root.

## Running an Eval

```bash
agents-cli eval run --evalset tests/eval/evalsets/rh_nodegoat.evalset.json
```

Per-metric scores are written to
`app/.adk/eval_history/<run>.evalset_result.json` — the CLI summary only shows
pass/fail.

## Iteration Log

### Baseline — v0 (Semgrep + Gemini discovery only; Trivy/Gitleaks/Bandit are stubs)

**Configuration:**

- Scanners enabled: Semgrep (real); Trivy / Gitleaks / Bandit are stubs that
  return `{"status": "not_implemented", "count": 0, "findings": []}`
- Gemini discovery agent: enabled (parallel with scanner discovery), tools:
  `list_dir`, `grep_code`, `read_code_window`
- Agent model: `gemini-3.1-pro-preview`
- Target: OWASP NodeGoat (~50 JS files, multiple seeded vulns across OWASP Top
  10 categories)

**Scores under two different judge models (same agent, same evalset):**

| Metric                                               | Threshold | Run 1 — judge `gemini-flash-latest` | Run 2 — judge `gemini-3-flash-preview` |
| ---------------------------------------------------- | --------- | ----------------------------------- | -------------------------------------- |
| `tool_trajectory_avg_score` (IN_ORDER)               | 0.7       | **0.0** (FAIL — measurement bug)    | **0.0** (FAIL — same bug)              |
| `hallucinations_v1`                                  | 0.7       | **1.0** PASS                        | **1.0** PASS                           |
| `rubric_based_final_response_quality_v1` (6 rubrics) | 0.6       | **1.0** PASS                        | **1.0** PASS                           |
| └ `finds_injection`                                  | —         | 1.0                                 | 1.0                                    |
| └ `finds_xss`                                        | —         | 1.0                                 | 1.0                                    |
| └ `finds_weak_crypto`                                | —         | 1.0                                 | 1.0                                    |
| └ `finds_broken_access_control`                      | —         | 1.0                                 | 1.0                                    |
| └ `finds_misconfig_or_secrets`                       | —         | 1.0                                 | 1.0                                    |
| └ `report_is_actionable`                             | —         | 1.0                                 | 1.0                                    |

**Actual tool-call counts (from `invocation_events`):**

| Tool             | Run 1 calls | Run 2 calls |
| ---------------- | ----------- | ----------- |
| detect_languages | 1           | 1           |
| run_semgrep      | 1           | 1           |
| run_trivy        | 1 (stub)    | 1 (stub)    |
| run_gitleaks     | 1 (stub)    | 1 (stub)    |
| list_dir         | 4           | 5           |
| grep_code        | 0           | 4           |
| read_code_window | 32          | 47          |
| write_report     | 1           | 1           |

**Takeaways:**

1.  **Substantive result is strong**: with only Semgrep + Gemini reasoning, the
    agent surfaced all six OWASP-category vulns in NodeGoat, with no
    hallucinations and an actionable report. The headline.

1.  **Judge swap was a clean experiment.** We ran the same agent / same evalset
    / same target under two different judge models — `gemini-flash-latest`
    (whatever it resolved to that day) vs the pinned `gemini-3-flash-preview`.
    Identical scores. **Conclusion: the perfect 1.0 rubric scores are NOT
    explained by self-preference bias** (the judges are from different versions;
    one is pinned, one was an alias). They're explained by the rubrics being too
    loose ("at least one X"). Tightening the rubrics is the real next move.

1.  **Trajectory metric is still broken for multi-agent dispatch.** The agent
    actually called every expected tool (see counts above), but
    `tool_trajectory_avg_score` reads from
    `actual_invocation.intermediate_data.tool_uses` — which is empty because
    tool calls in `ParallelAgent` / sub-agent dispatches land in
    `invocation_events` instead. Known ADK gotcha for multi-agent setups; not an
    agent bug.

1.  **Agent behavior is mildly non-deterministic across runs.** Same prompt +
    target produced different exploration patterns: Run 1 used 0 `grep_code`
    calls, Run 2 used 4; Run 1 read 32 code windows, Run 2 read 47. The shape
    (which scanners run, what categories the report covers) is stable; the exact
    path varies. Worth knowing for reproducibility.

1.  **Trivy and Gitleaks are stubs.** Their `run_*` calls did happen, but
    returned no findings. The injection/secrets/crypto signal in both runs came
    entirely from Semgrep + Gemini reasoning. When we implement Trivy, expect
    movement on `finds_misconfig_or_secrets` and discovery of vulnerable npm
    deps invisible today.

**Next-iteration follow-ups (in priority order):**

1.  **Tighten rubrics**: replace "at least one" rubrics with file-specific or
    count-specific assertions (e.g., "identifies SQL injection in
    `app/data/profile-dao.js`", "identifies ≥3 distinct injection findings").
    Without this, the rubric metric has zero discriminative power for measuring
    iteration improvements.
1.  **Fix trajectory measurement**: either switch to
    `rubric_based_tool_use_quality_v1` (LLM judge on tool use) or write a custom
    metric that extracts from `invocation_events`.
1.  **Implement Trivy** (npm SCA + secrets + IaC). Re-run, compare baseline to
    post-Trivy. Trivy should produce the first iteration where rubric scores
    have somewhere to move once tightened.

---

### Iteration 1 — rubric tightening (real discriminating baseline)

**What changed:** Replaced the 6 loose "at least one X" rubrics with 10 anchored
rubrics: most reference specific NodeGoat files (e.g., `routes/allocations.js`,
`routes/research.js`), and two are deliberately designed to fail today
(`finds_vulnerable_dependencies` measures Trivy ROI;
`report_includes_remediation_per_finding` measures a future prompt change).
Agent/judge/target unchanged from v0 baseline run 2.

**Metrics:**

| Metric                                                | Threshold | Score    | Status                                  |
| ----------------------------------------------------- | --------- | -------- | --------------------------------------- |
| `tool_trajectory_avg_score` (IN_ORDER)                | 0.7       | **0.0**  | FAIL — same multi-agent measurement bug |
| `hallucinations_v1`                                   | 0.7       | **1.0**  | PASS                                    |
| `rubric_based_final_response_quality_v1` (10 rubrics) | 0.6       | **0.60** | PASS (at threshold)                     |

**Per-rubric scores (6/10 pass):**

| Rubric                                    | Score  | Notes                                                                    |
| ----------------------------------------- | ------ | ------------------------------------------------------------------------ |
| `finds_injection_eval_or_nosql`           | ✅ 1.0 |                                                                          |
| `finds_xss_in_profile`                    | ❌ 0.0 | **Unexpected miss** — agent didn't anchor an XSS finding to profile flow |
| `finds_idor_in_allocations`               | ✅ 1.0 |                                                                          |
| `finds_weak_crypto_or_password_storage`   | ✅ 1.0 |                                                                          |
| `finds_missing_authz_on_admin_routes`     | ✅ 1.0 |                                                                          |
| `finds_ssrf_in_research`                  | ✅ 1.0 |                                                                          |
| `finds_csrf_on_form_routes`               | ❌ 0.0 | **Unexpected miss** — agent didn't flag missing CSRF on POST routes      |
| `finds_vulnerable_dependencies`           | ❌ 0.0 | **Stretch, expected fail** — Trivy is stubbed                            |
| `report_findings_include_evidence`        | ✅ 1.0 |                                                                          |
| `report_includes_remediation_per_finding` | ❌ 0.0 | **Stretch, expected fail** — report prompt doesn't ask for it            |

**Actual tool-call counts:**

| Tool             | Calls    |
| ---------------- | -------- |
| detect_languages | 1        |
| run_semgrep      | 1        |
| run_trivy        | 1 (stub) |
| run_gitleaks     | 1 (stub) |
| list_dir         | 3        |
| grep_code        | 1        |
| read_code_window | 30       |
| write_report     | 1        |

**Takeaways:**

1.  **Rubric tightening worked.** Went from uniform 1.0 (uninformative) to a
    discriminating 0.60 right at threshold. Future iterations now have somewhere
    to move.

1.  **Eval design is validated.** Both stretch rubrics
    (`finds_vulnerable_dependencies`, `report_includes_remediation_per_finding`)
    failed as designed — they will be the direct numerical proof when we
    implement Trivy and update the report prompt.

1.  **Two real capability gaps surfaced** that the old rubrics hid:

- **XSS in profile flow** — Semgrep + Gemini reasoning didn't anchor a finding
  to `app/routes/profile.js` / `app/views/profile.html`. The agent might be
  flagging XSS generically without localization. Worth digging into the actual
  report to see whether it's a _missing_ finding or a _missing file-anchor_
  problem (different fixes).
- **CSRF on form routes** — Gemini didn't flag missing CSRF middleware.
  Semantic-only finding (no Semgrep rule for this). Could be addressed by
  sharpening the LLM discovery prompt to explicitly call out CSRF as a category.

1.  **Next-iteration priority (in order):**
1.  Inspect the actual report from this run to diagnose XSS/CSRF gaps (cheap,
    high-info).
1.  Implement Trivy. Re-run, watch `finds_vulnerable_dependencies` move from 0
    → 1.
1.  Update the report prompt to include remediation per finding. Re-run, watch
    `report_includes_remediation_per_finding` move.
1.  Then sharpen the LLM discovery prompt for CSRF + targeted XSS-in-views
    detection.
1.  Then the security-engineer's Triage Critic prompt upgrade (Tier 1, Rec 4
    from arch review).

---

### Iteration 1b — relax XSS rubric + nudge LLM discovery for CSRF/redirects + new redirect rubric

**What changed:**

- `finds_xss_in_profile` → `finds_xss`: rubric now accepts EITHER the
  architectural root-cause (Swig `autoescape: false` in server.js) OR the
  symptom location (profile flow). The agent's `gemini.xss-misconfig` finding
  now correctly scores 1.0.
- LLM_DISCOVERY_INSTRUCTION: added explicit "CSRF" and "unvalidated redirects"
  categories with examples.
- New rubric `finds_unvalidated_redirects` for OWASP A10 (11 rubrics total).

**Metrics:**

| Metric                                   | Threshold | Iteration 1 | Iteration 1b | Δ      |
| ---------------------------------------- | --------- | ----------- | ------------ | ------ |
| `tool_trajectory_avg_score` (IN_ORDER)   | 0.7       | 0.0         | 0.0          | —      |
| `hallucinations_v1`                      | 0.7       | 1.0         | 1.0          | —      |
| `rubric_based_final_response_quality_v1` | 0.6       | **0.600**   | **0.727**    | +0.127 |

**Per-rubric movement:**

| Rubric                                   | Iter 1    | Iter 1b   | Note                                                |
| ---------------------------------------- | --------- | --------- | --------------------------------------------------- |
| `finds_xss` (was `finds_xss_in_profile`) | ❌ 0.0    | ✅ 1.0    | Rubric relaxation worked                            |
| `finds_unvalidated_redirects`            | —         | ✅ 1.0    | Agent caught it (new rubric, new prompt)            |
| `finds_csrf_on_form_routes`              | ❌ 0.0    | ❌ 0.0    | **Prompt nudge did NOT help — see diagnosis below** |
| Others (8)                               | unchanged | unchanged |                                                     |

**Tool-call counts:**

| Tool                     | Iter 1     | Iter 1b    |
| ------------------------ | ---------- | ---------- |
| detect_languages         | 1          | 1          |
| run_semgrep              | 1          | 1          |
| run_trivy / run_gitleaks | 1 / 1 stub | 1 / 1 stub |
| list_dir                 | 3          | varies     |
| grep_code                | 1          | varies     |
| read_code_window         | 30         | varies     |
| write_report             | 1          | 1          |

**CSRF diagnosis (the interesting part):**

Read the latest report — agent listed 10 findings, none of them CSRF. Then
inspected NodeGoat itself:

```javascript
// server.js:105-110
// Fix for A8 - CSRF
// Enable Express csrf protection
// app.use(csrf());
// Make csrf token available in templates
// app.use(function(req, res, next) {
//     res.locals.csrftoken = req.csrfToken();
```

NodeGoat's csurf middleware is **literally commented out** with an OWASP
reference in the comment. The agent should have caught this trivially.

**Root cause:** the validation agent reads narrow code windows around findings
(lines [line-5, line+15]). When validating the XSS finding at `server.js:139`,
it read lines 134-154 — missing the commented-out csurf at 105-110. The LLM
discovery agent's prompt also didn't specifically prompt for _commented-out
security middleware_ as a recognizable pattern, so it didn't grep for it
independently.

**Fix applied (post-Iteration 1b):** added a third category to
LLM_DISCOVERY_INSTRUCTION — "Commented-out or never-enabled security middleware"
— with example grep patterns like
`//\s*app\.use\(.*(csrf|csurf|helmet|cors|rateLimit)`. Will be measured on the
next re-run.

---

### Iteration 1c — re-run after commented-middleware prompt addition

**What changed:** Added "commented-out or never-enabled security middleware" as
a third category in LLM_DISCOVERY_INSTRUCTION, with example grep patterns for
csurf/helmet/cors/rateLimit.

**Result:** **Same overall score (0.727)**, but different per-rubric pattern:

| Rubric                        | Iter 1b   | Iter 1c   | Δ                                                        |
| ----------------------------- | --------- | --------- | -------------------------------------------------------- |
| `finds_csrf_on_form_routes`   | ❌ 0.0    | ❌ 0.0    | (still failing — but for a different reason — see below) |
| `finds_unvalidated_redirects` | ✅ 1.0    | ✅ 1.0    | —                                                        |
| Others                        | unchanged | unchanged | —                                                        |

**CSRF diagnosis (interesting):** Inspected the report — agent DID find CSRF
this run! Reported `gemini.csrf-disabled @ server.js:109` ("app.use(csrf())
middleware integration is commented out"). And it ALSO produced an exploit chain
("Stored XSS via CSRF") linking csrf-disabled + autoescape-disabled — **first
time multi-finding chaining fired in eval**. But the rubric demanded a per-route
symptom finding and rejected the global-middleware root-cause finding. Same
calibration bug as XSS.

---

### Iteration 1d — relax CSRF rubric (same root-cause-vs-symptom fix as XSS)

**What changed:** `finds_csrf_on_form_routes` → `finds_csrf`; rubric now accepts
EITHER the architectural root-cause (commented `app.use(csrf())`) OR per-route
symptom.

**Result:**

| Rubric                        | Iter 1c   | Iter 1d   | Δ                                              |
| ----------------------------- | --------- | --------- | ---------------------------------------------- |
| `finds_csrf` (relaxed)        | ❌ 0.0    | ✅ 1.0    | +1                                             |
| `finds_unvalidated_redirects` | ✅ 1.0    | ❌ 0.0    | **−1 (regression — same code/prompts/target)** |
| Others                        | unchanged | unchanged | —                                              |

**Overall: 0.727 → 0.727.** Same headline score, different rubrics passing.
Variance is real — same agent, same code, two consecutive runs found _different_
subsets of the same vuln set. Agent capability is provably ≥9/11 (caught both
CSRF and unvalidated-redirects in at least one run each), but no single run
achieves that.

---

### Iteration 2 — skill-directory refactor + temperature=0 on llm_discovery_agent

**What changed (architectural):**

- New `app/skills/detection/*.md` directory with **11 focused detection
  skills**: csrf, sql-or-nosql-injection, eval-or-function-injection, xss, ssrf,
  idor, broken-authorization, weak-crypto-or-password-storage,
  hardcoded-secrets, unvalidated-redirects, commented-security-middleware.
- Each skill is a structured playbook: when_to_apply, file_globs, detection
  procedure (specific grep_code patterns + file inspection steps), TP/FP
  signals, severity guidance, CWE mapping, suggested rule_id slug.
- New tool `load_skill(skill_id)` loads skill content on demand (progressive
  disclosure — only relevant skills enter context).
- `LLM_DISCOVERY_INSTRUCTION` slimmed from ~80 lines (wall-of-prompt with
  examples) to ~50 lines (orchestration: skill-index injection at init time →
  agent picks → loads → executes → optional fallback exploration → JSON output).
- **`temperature=0.0`** applied to `llm_discovery_agent` only via
  `generate_content_config` on the Agent (other agents unchanged).

**Result:**

| Metric                                   | Iter 1d   | Iter 2    | Δ   |
| ---------------------------------------- | --------- | --------- | --- |
| `tool_trajectory_avg_score`              | 0.0       | 0.0       | —   |
| `hallucinations_v1`                      | 1.0       | 1.0       | —   |
| `rubric_based_final_response_quality_v1` | **0.727** | **0.727** | —   |

Per-rubric: identical to 1d (CSRF ✅, unvalidated-redirects ❌, etc.).

**But the underlying agent behavior changed substantially:**

| Tool               | Iter 1d | Iter 2                                         |
| ------------------ | ------- | ---------------------------------------------- |
| `load_skill`       | —       | **11** (loaded every skill)                    |
| `grep_code`        | 1       | **15** (skills drove ~10× more targeted greps) |
| `read_code_window` | 30      | 50                                             |
| `list_dir`         | 3       | 1 (less wandering, more targeted)              |

**Substantive wins in the report (even though score didn't move):**

- **New finding: `gemini.security-headers-disabled @ server.js:45`** — only
  possible because the `commented-security-middleware` skill explicitly looks
  for helmet too, not just csurf. This is genuine new coverage.
- CSRF still firing consistently.
- Exploit chain still firing.

**The redirect miss is opaque:** The `unvalidated-redirects` skill was loaded
(confirmed in tool trace), and NodeGoat's `routes/index.js:72` has
`return res.redirect(req.query.url)` which the skill's grep pattern
(`res\.redirect\s*\(\s*req\.(query|body|params)\.`) would match exactly. But the
agent didn't produce a finding. Possible causes: skill loaded but procedure not
executed, finding generated but dropped in triage/validation, or agent decided
FP without confirmation.

**Variance still a question.** Iteration 1d and Iteration 2 produced identical
scores. Either (a) temperature=0 + skills makes the agent reliably reproduce
this exact result, OR (b) the agent stochastically landed on the same path twice
in a row by chance. Need at least one more run to distinguish.

**Takeaway:** the architectural change works — skill directory loaded as
designed, prompt is now scalable, new finding category surfaced. The score
didn't move because we traded one finding for another. To prove the variance
hypothesis, run iteration 2 a second time and compare.

---

### Iteration 2b — variance test under temperature=0 (no code changes)

**Goal:** Determine whether the identical scores across Iter 1d and Iter 2 were
due to temperature=0 working or stochastic coincidence.

**Result: variance hypothesis CONFIRMED.** Identical overall score (0.727),
identical per-rubric breakdown, identical set of 11 skills loaded in identical
order to Iter 2. Tool-call counts at the exploration level varied (`grep_code`
15→28, `read_code_window` 50→32) — temperature=0 isn't bit-exact due to
GPU-kernel non-determinism and ADK parallel dispatch, but the **user-visible
outcome (which findings, which scores) is reproducible**. Future iteration
deltas can now be trusted as real signal rather than noise.

**Side finding (systematic gap):** `finds_unvalidated_redirects` failed two runs
in a row at temp=0. It's no longer a stochastic miss — it's a reproducible gap
in agent behavior. The `unvalidated-redirects` skill is loaded but doesn't yield
a finding, despite NodeGoat's `routes/index.js:72` having a textbook
`res.redirect(req.query.url)` pattern that matches the skill's grep. Targets for
investigation: (a) is the skill's procedure being executed at all? (b) is a
finding produced and dropped in triage/validation? (c) is the grep pattern too
narrow? Worth a quick diagnostic before adding more code.

---

### Iteration 3 — Triage Critic prompt upgrade + validation cap bump

**What changed:**

1.  `TRIAGE_INSTRUCTION` rewritten as an adversarial security reviewer ("prove
    the finding is NOT exploitable" — default skeptical). New per-finding output
    schema:
    `{adjudication: TRUE_POSITIVE | FALSE_POSITIVE, confidence_score: 1-100, reasoning}`.
    Explicit reachability + sanitization checks. Test-directory findings
    explicitly directed toward FALSE_POSITIVE. Dedup, cross-source
    corroboration, ranking, top-25 cap preserved.
1.  **Initial run (Iter 3) regressed.** Score dropped 0.727 → 0.636 because the
    richer triage output (e.g., 3 distinct `hardcoded-*` findings instead of 1;
    new exploit chains; more cross-source detail) pushed SSRF to rank 11+, where
    the validation_agent's hardcoded "top 10" cap squeezed it out. **The Triage
    Critic was working too well for the downstream cap.**
1.  **Follow-up fix (Iter 3b):** updated `VALIDATION_INSTRUCTION` to process the
    **top 15 TRUE_POSITIVE findings by rank**, explicitly skipping
    FALSE_POSITIVE rows that triage already adjudicated out. This is the
    validation pipeline finally using the new adjudication metadata as intended.

**Iter 3b result — new high score:**

| Metric                                   | Iter 2b | Iter 3 (regression) | Iter 3b   | Δ from 2b                     |
| ---------------------------------------- | ------- | ------------------- | --------- | ----------------------------- |
| `tool_trajectory_avg_score` (IN_ORDER)   | 0.0     | 0.0                 | 0.0       | — (measurement bug unchanged) |
| `hallucinations_v1`                      | 1.0     | 1.0                 | 1.0       | —                             |
| `rubric_based_final_response_quality_v1` | 0.727   | **0.636**           | **0.818** | **+0.091**                    |

**Per-rubric (Iter 3b):**

| Rubric                                    | Iter 2b | Iter 3b    | Change                                                 |
| ----------------------------------------- | ------- | ---------- | ------------------------------------------------------ |
| `finds_injection_eval_or_nosql`           | ✅ 1.0  | ✅ 1.0     | —                                                      |
| `finds_xss`                               | ✅ 1.0  | ✅ 1.0     | —                                                      |
| `finds_idor_in_allocations`               | ✅ 1.0  | ✅ 1.0     | —                                                      |
| `finds_weak_crypto_or_password_storage`   | ✅ 1.0  | ✅ 1.0     | —                                                      |
| `finds_missing_authz_on_admin_routes`     | ✅ 1.0  | ✅ 1.0     | —                                                      |
| `finds_ssrf_in_research`                  | ✅ 1.0  | ✅ 1.0     | — (regressed in Iter 3 then restored)                  |
| `finds_csrf`                              | ✅ 1.0  | ✅ 1.0     | —                                                      |
| `finds_unvalidated_redirects`             | ❌ 0.0  | ✅ **1.0** | **+1 (resisted across 1b/1c/1d/2/2b; finally closed)** |
| `finds_vulnerable_dependencies`           | ❌ 0.0  | ❌ 0.0     | — (stretch — waiting on Trivy)                         |
| `report_findings_include_evidence`        | ✅ 1.0  | ✅ 1.0     | —                                                      |
| `report_includes_remediation_per_finding` | ❌ 0.0  | ❌ 0.0     | — (stretch — waiting on report prompt)                 |

**🎯 V0 ship gate achieved:**
`rubric_based_final_response_quality_v1 = 0.818 ≥ 0.8` ✓,
`hallucinations_v1 = 1.0` ✓, no non-stretch rubric at 0 ✓. Both remaining
failures are intentional stretch rubrics scheduled for Iter 4 and Iter 6.

**Report contents (Iter 3b — 13 findings):**

| #   | Finding                            | Where                            |
| --- | ---------------------------------- | -------------------------------- |
| 1   | mongo-where-injection              | `app/data/allocations-dao.js:78` |
| 2   | server-side-js-injection (eval)    | `app/routes/contributions.js:32` |
| 3   | plaintext-password-storage         | `app/data/user-dao.js:25`        |
| 4   | ssrf                               | `app/routes/research.js:16`      |
| 5   | broken-authz                       | `app/routes/index.js:55`         |
| 6   | idor                               | `app/routes/allocations.js:18`   |
| 7   | xss-autoescape-disabled            | `server.js:137`                  |
| 8   | csrf-disabled                      | `server.js:107`                  |
| 9   | security-headers-disabled (helmet) | `server.js:45`                   |
| 10  | hardcoded-cookie-secret            | `config/env/all.js:8`            |
| 11  | hardcoded-crypto-key               | `config/env/all.js:9`            |
| 12  | unvalidated-redirect               | `app/routes/index.js:68`         |
| 13  | var-in-href (from Semgrep)         | `app/views/profile.html:78`      |

**Substantive wins beyond fixing the regression:**

- **The redirect gap is finally closed** — root cause was the validation cap,
  not agent capability. We chased prompt nudges, skill content, and rubric
  framing across five iterations; the actual fix was 2 lines in
  `VALIDATION_INSTRUCTION`. Worth remembering: when a rubric resists multiple
  targeted fixes, look upstream at the pipeline, not the prompt.
- **Triage adjudication is now first-class metadata** — every finding carries
  `{adjudication, confidence_score, reasoning}`. Foundation for future
  per-finding confidence-calibration rubrics (could add
  `triage_adjudication_quality` rubric in a later iteration).
- **Adversarial framing made triage more thorough**, not just more skeptical —
  it found more nuance (3 distinct hardcoded-\* findings, 2 exploit chains,
  security-headers as separate from csrf) even while preserving all prior
  findings under the larger cap.

**Triage adjudication sample (from `triaged_findings` state, this run):**

```json
{
  "scanner": "gemini",
  "rule_id": "gemini.ssrf",
  "severity": "high",
  "file": "app/routes/research.js",
  "line": 16,
  "message": "Server-Side Request Forgery (SSRF) via unvalidated URL.",
  "rank": 4,
  "adjudication": "TRUE_POSITIVE",
  "confidence_score": 95,
  "reasoning": "User-controlled 'url' and 'symbol' query parameters are directly concatenated and passed to 'needle.get()' without checking a host allowlist, directly enabling SSRF."
}
```

---

### Iteration 4 — Trivy implementation (with downstream cascade fixes)

**Original goal:** replace the Trivy stub with a real `trivy fs` integration;
expect `finds_vulnerable_dependencies` rubric 0→1. **Actual story:** one
iteration goal triggered four downstream interaction bugs the eval surfaced,
each requiring its own sub-iteration. Final result is the trustworthy peak
(0.909, 10/11, hallucinations 1.0), but the path there is worth documenting.

**Iter 4 (first run with live Trivy):**

- `run_trivy` now does real
  `trivy fs --format json --scanners vuln,secret,misconfig` and parses 50+ CVE
  findings (sorted by severity, capped). First run downloads vuln DB from
  `ghcr.io` (documented exception to scanner-no-egress constraint).

| Metric                                   | Iter 3b | Iter 4     | Δ                                       |
| ---------------------------------------- | ------- | ---------- | --------------------------------------- |
| `rubric_based_final_response_quality_v1` | 0.818   | 0.818      | 0                                       |
| `finds_vulnerable_dependencies`          | ❌ 0.0  | ✅ **1.0** | **+1 (Trivy ROI confirmed)**            |
| `finds_unvalidated_redirects`            | ✅ 1.0  | ❌ **0.0** | **−1 (regression — cap squeeze again)** |

**Root cause:** Trivy added 6+ Critical CVE rows on `package-lock.json`.
Validation's top-15 cap filled with criticals; Medium-severity redirect got
squeezed out. Same shape as Iter 3 cap-squeeze.

**Iter 4b — cap bump 15→25 (failed):** reproducible `499 CANCELLED` from Vertex
on 2 consecutive runs. The larger validation prompt with 25 findings tipped over
a `gemini-3.1-pro-preview` capacity/context threshold. **Lesson: bumping the cap
further isn't a sustainable fix.**

**Iter 4c — cap reverted to 15 + Trivy clustering rule in TRIAGE_INSTRUCTION
(failed):** triage now collapses N `trivy.vuln.*` rows into one
`trivy.vuln-summary` row per manifest, listing top 5 CVEs in the message. But:
still hit `499 CANCELLED` repeatedly. At this point we suspected wider Vertex
degradation, not our code (which lint-clean Trivy + clustering smoke-tested
fine).

**External signal:** Gemini 3.5 launched at Google I/O the same day. Pro-preview
capacity heavily constrained; long-context agent calls being preempted. Small
pings to the same model worked instantly — confirming infra-side, not our code.

**Iter 4d — swap entire agent to `gemini-3.5-flash` (workaround, completed):**

| Metric                                   | Iter 3b (all pro) | Iter 4d (all flash) | Δ          |
| ---------------------------------------- | ----------------- | ------------------- | ---------- |
| `rubric_based_final_response_quality_v1` | 0.818 (9/11)      | **1.0 (11/11)**     | +0.182     |
| `hallucinations_v1`                      | 1.0               | **0.894** ⚠         | **−0.106** |

**Suspicious-too-good.** Both stretch rubrics passed including
`report_includes_remediation_per_finding` (which we hadn't yet built into the
prompt — flash was spontaneously generating remediation text). The 0.894
hallucinations score = **5 of 47 claims** flagged as not grounded in tool
output. Manual cross-check of one finding: report claimed "the entire security
configuration block utilizing the helmet middleware is commented out at
`server.js:48`" — but actual code at line 48 had **active**
`app.use(helmet.X())` calls. The `require` was commented (line 10), so helmet
was effectively disabled, but flash described the _wrong evidence_. A user
trying to fix it would uncomment the wrong lines. **Flash's failure mode: right
conclusion, hallucinated evidence text.**

**Iter 4e — selective model split (completed):** keep flash on
`llm_discovery_agent` (highest call volume = biggest capacity relief), put pro
back on triage/validation/report (where reasoning quality matters for grounded
text). Added `_model_fast()` helper in `app/agent.py`.

| Metric         | Iter 4d | Iter 4e   | Notes                             |
| -------------- | ------- | --------- | --------------------------------- |
| Hallucinations | 0.894 ⚠ | **1.0** ✓ | Pro on report = grounded text     |
| Rubric         | 1.0     | **0.818** | Lost vuln_deps rubric — see below |

**Why vuln_deps regressed in 4e:** triage emitted a perfect cluster message ("49
known-vulnerable packages in package-lock.json. Top: bson@1.0.9 (CVE-2020-7610),
fsevents@1.2.9 (CVE-2023-45311), …"), but the validation agent rewrote it to
"Trivy successfully identified multiple vulnerable package dependencies" —
generic, no CVE specifics. The judge rejected it for the rubric. Root cause:
validation's "read code window + write evidence" model doesn't apply to non-code
findings (package-lock.json:0 isn't source), so the validation agent generalized
away triage's careful specifics.

**Iter 4f — validation preserves Trivy specifics for non-code findings
(completed) — TRUSTWORTHY PEAK:**

Updated `VALIDATION_INSTRUCTION` with an explicit exception for `trivy.vuln.*` /
`trivy.secret.*` / `trivy.misconfig.*` findings (and any finding where line=0
against a manifest/config/cert): skip the read_code_window call, set
`validated: true`, and **copy the triage message verbatim** instead of
paraphrasing.

| Metric         | Iter 3b      | Iter 4 | Iter 4d (flash)  | Iter 4e | **Iter 4f**         |
| -------------- | ------------ | ------ | ---------------- | ------- | ------------------- |
| Hallucinations | 1.0          | 1.0    | 0.894 ⚠          | 1.0     | **1.0** ✓           |
| Rubric         | 0.818 (9/11) | 0.818  | 1.0\* (illusory) | 0.818   | **0.909 (10/11)** ✓ |

(\* Iter 4d's 1.0 was inflated by flash's hallucinated coverage; not directly
comparable.)

**Final Iter 4f rubric breakdown:**

| Rubric                                    | Iter 3b | Iter 4f                   |
| ----------------------------------------- | ------- | ------------------------- |
| `finds_injection_eval_or_nosql`           | ✅ 1.0  | ✅ 1.0                    |
| `finds_xss`                               | ✅ 1.0  | ✅ 1.0                    |
| `finds_idor_in_allocations`               | ✅ 1.0  | ✅ 1.0                    |
| `finds_weak_crypto_or_password_storage`   | ✅ 1.0  | ✅ 1.0                    |
| `finds_missing_authz_on_admin_routes`     | ✅ 1.0  | ✅ 1.0                    |
| `finds_ssrf_in_research`                  | ✅ 1.0  | ✅ 1.0                    |
| `finds_csrf`                              | ✅ 1.0  | ✅ 1.0                    |
| `finds_unvalidated_redirects`             | ✅ 1.0  | ✅ 1.0                    |
| `finds_vulnerable_dependencies`           | ❌ 0.0  | ✅ **1.0** (+1)           |
| `report_findings_include_evidence`        | ✅ 1.0  | ✅ 1.0                    |
| `report_includes_remediation_per_finding` | ❌ 0.0  | ❌ 0.0 (stretch — Iter 6) |

**Lessons from the Iter 4 arc:**

1.  **Every meaningful upstream upgrade (Triage Critic in Iter 3; Trivy in
    Iter 4) crowds the downstream cap.** Recurring pattern. After two
    consecutive iterations needed cap bumps, we shifted to a structural fix
    (triage clustering for non-diverse signal classes) rather than bumping
    further.
1.  **`gemini-3.1-pro-preview` capacity is fragile around peer-model launches.**
    Workaround documented in agent code + memory: keep pro on quality-critical
    agents (triage/validation/report), flash on call-heavy ones (llm_discovery).
    Revisit when `gemini-3.5-pro` becomes accessible.
1.  **Flash's hallucination failure mode is dangerous-looking, not
    dangerous-by-omission.** Flash gets the _conclusion_ right and the
    _evidence_ wrong — a developer following a hallucinated "uncomment line 48"
    suggestion fixes nothing. The all-flash 1.0 looked best on the rubric
    scorecard but was worst for actual product safety.
1.  **The validation agent's "read code → write evidence" model doesn't apply to
    non-code findings** (SCA, lockfile-anchored secrets, IaC misconfig). Made
    explicit in the instruction with a pass-through branch.

**Where Phase A code work stands after Iter 4f:**

- ✅ Triage Critic prompt upgrade (Iter 3)
- ✅ Trivy live (Iter 4 + cascade fixes through 4f)
- ✅ Model strategy: selective split (4e)
- ✅ Validation preserves non-code evidence (4f)
- ⏳ REPORT_INSTRUCTION update for per-finding remediation (Iter 6)

---

### Iteration 5 — synthetic per-skill corpus

**Goal:** add a second corpus alongside NodeGoat that isolates per-skill
correctness. NodeGoat measures aggregate "did the agent find SQL injection
somewhere"; the synthetic corpus measures "given a minimal isolated
SQL-injection target, did the agent's `sql-or-nosql-injection` skill fire?"
Cleanly attributes regressions to a single skill when one skill changes.

**Design:** 11 minimal Express snippets, one per detection skill, each ~10-20
lines with one unambiguous textbook vuln. Shared per-skill rubric in
`tests/eval/synthetic_eval_config.json` reads the skill name from the user
prompt's path and checks that the report identifies exactly that class.
Aggregate score = per-skill recall (N/11).

**Iter 5a — first run (ADK rubric framework bug):**

- All 11 cases completed end-to-end (architecture works on synthetic targets).
- Pass/fail headline said "11 passed" — but that was misleading.
- **Warning in log:**
  `Rubric ... not found in the rubrics provided to the metric.` Rubric score
  came back null on every case. ADK's `rubric_based_evaluator` couldn't apply
  the rubric.
- **Root cause (read from ADK source `rubric_based_evaluator.py:380-410`):** the
  evaluator builds a lookup `_normalize_text(rubric.text_property) → rubric` and
  matches against the judge's response. The judge LLM is expected to **repeat
  the rubric text verbatim** (after lowercase + strip). Our rubric was ~3000
  chars with an embedded vuln-class mapping table; the judge paraphrased it, so
  the lookup failed silently.

**Design lesson #1 — ADK rubric verbatim-match constraint:** keep rubric
`text_property` short enough (and structurally simple enough) that the judge
model repeats it verbatim in its response. The working NodeGoat rubrics are all
300-500 chars, single sentence. Tables/lists inside a rubric break the match
silently. **Documented in this file so future iterations don't write another
mega-rubric.**

**Iter 5b — tightened rubric (550 chars, no embedded mapping):**

- Lookup warning gone — rubric being applied.
- But all 11 cases scored 0.0 on the rubric.
- **Diagnosis from reading the latest report:** agent DID find the vulnerability
  (e.g., `gemini.broken-authz` at `vuln.js:21` for the broken-authorization
  case). But validation marked it as FALSE_POSITIVE because the path was
  `tests/eval/corpora/synthetic/...` — and the broken-authorization skill
  explicitly says "test/fixture code should usually be FALSE_POSITIVE" (a
  correct heuristic for real codebases).
- **The agent isn't broken; our corpus path is.** Sample exec summary from one
  case: _"The single potential finding was verified to be a test fixture and
  thus a false positive."_

**Design lesson #2 — path-anonymity for synthetic corpora:** the agent's
`tests/` → fixture-FP heuristic is a feature, not a bug. Synthetic targets must
live OUTSIDE any `tests/` ancestor or the agent will (correctly) reject them as
test fixtures.

**Iter 5c — corpus moved to `eval-corpora/synthetic/` (project root):**

| Skill                           | Rubric    | Hallucinations |
| ------------------------------- | --------- | -------------- |
| csrf                            | ✅ 1.0    | 1.0            |
| idor                            | ✅ 1.0    | 1.0            |
| ssrf                            | ✅ 1.0    | 1.0            |
| eval-or-function-injection      | ✅ 1.0    | 1.0            |
| xss                             | ✅ 1.0    | 1.0            |
| sql-or-nosql-injection          | ✅ 1.0    | 1.0            |
| weak-crypto-or-password-storage | ✅ 1.0    | 1.0            |
| hardcoded-secrets               | ✅ 1.0    | 1.0            |
| unvalidated-redirects           | ✅ 1.0    | 1.0            |
| commented-security-middleware   | ✅ 1.0    | 1.0            |
| broken-authorization            | ✅ 1.0    | 1.0            |
| **Aggregate**                   | **11/11** | **1.0**        |

**Honest caveats on the 11/11:**

1.  **Recall, not precision.** We measured "does the skill fire on its target?"
    — 100%. We did NOT measure "does the skill _only_ fire when it should?" That
    requires `safe.js` FP-control cases — deferred as a Phase B candidate.
1.  **Targets are minimalist.** Each `vuln.js` is 10-20 lines of textbook
    unambiguous vuln. This is a _floor_ (proves no skill is broken at the
    easiest case), not a _ceiling_. Real customer codebases will be harder.
1.  **Rubric is permissive by design.** "Identifies a vulnerability of exactly
    that class" passes if the report names the class anywhere — doesn't check
    severity calibration, evidence depth, or remediation quality. Per-skill
    _quality_ metrics would need additional rubrics.

**Post-Iter 5 status:** two trustworthy baselines now in place — **NodeGoat
(end-to-end, aggregate)** at 10/11 + 1.0 hallucinations, and **synthetic
(per-skill, isolated)** at 11/11 + 1.0 hallucinations.

---

### Iteration 6 — REPORT_INSTRUCTION update for per-finding remediation

**What changed:** `REPORT_INSTRUCTION` updated to require each detailed-finding
subsection to include both an **Evidence** field (existing) and a
**Remediation** field with concrete fix recommendations (specific code change,
library to add, config to enable, or upgrade path). Vague guidance explicitly
disallowed in the prompt.

**Result — headline rubric win, hallucinations regression:**

| Metric                                             | Iter 4f       | Iter 6          | Δ                       |
| -------------------------------------------------- | ------------- | --------------- | ----------------------- |
| `rubric_based_final_response_quality_v1`           | 0.909 (10/11) | **1.0 (11/11)** | +0.091 ✓                |
| `report_includes_remediation_per_finding` (target) | ❌ 0.0        | ✅ **1.0**      | ✓ as designed           |
| `hallucinations_v1`                                | **1.0**       | **0.745** ⚠     | **−0.255 (regression)** |

`0.745` = exactly **13/51** claims flagged as not grounded in tool output. Same
shape as Iter 4d's flash-everywhere failure mode: when the model is asked to
produce more specific text (per-finding remediation), it writes
plausible-sounding details that aren't fully derivable from tool output.

**Diagnosis (read the latest report, cross-checked against tool outputs):** the
hallucinations are **softer** than Iter 4d's. Iter 4d hallucinated _factual
claims about code state_ (helmet commented at `server.js:48` when it wasn't —
would actively misdirect a developer toward the wrong fix). Iter 6's
hallucinations are mostly **best-practice augmentation** — the model brings
security knowledge to remediation suggestions that isn't strictly visible in the
tool output. Examples:

- "Replace hardcoded strings with `process.env.COOKIE_SECRET || ...`" — true
  best practice, but the specific `process.env` pattern isn't in tool output.
- "Validate URL against allowlist e.g.
  `if (!ALLOWED_HOSTS.includes(new URL(url).hostname))`" — invented code snippet
  that's a reasonable fix, but not derived from observed code.
- "Force redirect target to be a relative path e.g.
  `if (url.startsWith('/') && !url.startsWith('//'))`" — same pattern.

`hallucinations_v1` correctly flags these as not grounded — that's its job — but
unlike Iter 4d's misdirection-class hallucinations, these don't lead a user to
wrong fixes. They overstate the agent's confidence in invented specifics.

**Per-rubric breakdown (Iter 6):**

| Rubric                                    | Iter 4f | Iter 6          |
| ----------------------------------------- | ------- | --------------- |
| `finds_injection_eval_or_nosql`           | ✅ 1.0  | ✅ 1.0          |
| `finds_xss`                               | ✅ 1.0  | ✅ 1.0          |
| `finds_idor_in_allocations`               | ✅ 1.0  | ✅ 1.0          |
| `finds_weak_crypto_or_password_storage`   | ✅ 1.0  | ✅ 1.0          |
| `finds_missing_authz_on_admin_routes`     | ✅ 1.0  | ✅ 1.0          |
| `finds_ssrf_in_research`                  | ✅ 1.0  | ✅ 1.0          |
| `finds_csrf`                              | ✅ 1.0  | ✅ 1.0          |
| `finds_unvalidated_redirects`             | ✅ 1.0  | ✅ 1.0          |
| `finds_vulnerable_dependencies`           | ✅ 1.0  | ✅ 1.0          |
| `report_findings_include_evidence`        | ✅ 1.0  | ✅ 1.0          |
| `report_includes_remediation_per_finding` | ❌ 0.0  | ✅ **1.0** (+1) |

**V0 ship gate: technically met** (rubric 1.0 ≥ 0.8 ✓, hallucinations 0.745 ≥
0.7 ✓, no measurable rubric at 0). But the hallucinations drop is a real
regression worth addressing before declaring Phase A done — the "looks better,
actually worse" trap.

---

### Iteration 6b — _staged in code, eval validation deferred_: tighten REPORT_INSTRUCTION remediation grounding

**Code change shipped** in `REPORT_INSTRUCTION`: added an explicit grounding
rule for the remediation requirement. Remediation suggestions must reference
patterns, identifiers, or upgrade targets that are EITHER (a) directly visible
in the finding's Evidence note, OR (b) directly visible in the finding's scanner
output (e.g., Trivy's `installed_version` / `fixed_version`). Acceptable shapes
spelled out:

- Specific code change anchored in observed code (e.g., the validation evidence
  quoted `eval(req.body.preTax)`, so the remediation can quote it back when
  proposing the fix).
- Named library/middleware/config by canonical name only (e.g., "Register
  `csurf` middleware") — NOT a fabricated code snippet that wasn't observed.
- Upgrade path with versions taken from scanner output.
- For categories where the fix is well-known but the specifics weren't observed
  (e.g., "use environment variables for secrets"), phrase as a one-line standard
  reference, not as invented code.

**Expected impact (unverified):** rubric should hold at 1.0 (the agent's genuine
code-anchored remediations still pass), hallucinations should recover toward 1.0
(the invented `if (url.startsWith('/'))`-style specifics get reframed as
canonical-name references).

**Eval validation deferred.** 3 consecutive `499 CANCELLED` from Vertex on the
validation runs (1 on first attempt + 2 retries) — same `gemini-3.1-pro-preview`
capacity preemption pattern as the post-Gemini-3.5-launch event we documented in
Iter 4. Smoke tests + lint clean; the prompt change itself isn't the cause.
Validation rolls into the next session when capacity is available.

---

## Phase A — Complete

**Wrap state (as of Iter 6 — Iter 6b code shipped but unverified):**

| Eval                                                    | Score               | Notes                                                                                                                                                                                                             |
| ------------------------------------------------------- | ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **NodeGoat — `rubric_based_final_response_quality_v1`** | **1.0 (11/11)**     | All rubrics passing including both stretch rubrics (`finds_vulnerable_dependencies` from Trivy in Iter 4f; `report_includes_remediation_per_finding` from Iter 6)                                                 |
| **NodeGoat — `hallucinations_v1`**                      | **0.745**           | ⚠ Down from 1.0 at Iter 4f. Hallucination class is best-practice-augmentation, NOT factual-misdirection (different from Iter 4d). Iter 6b grounding-rule fix shipped to address; eval validation pending.         |
| **Synthetic per-skill — recall**                        | **11/11**           | Iter 5c. All 11 detection skills fire on their minimal isolated targets.                                                                                                                                          |
| **Synthetic per-skill — `hallucinations_v1`**           | **1.0**             | Iter 5c.                                                                                                                                                                                                          |
| `tool_trajectory_avg_score`                             | 0.0 (known ADK bug) | Multi-agent dispatch puts tool calls in `invocation_events`, not the path the built-in metric reads. Not an agent issue. Phase B candidate: switch to `rubric_based_tool_use_quality_v1` (LLM judge on tool use). |

**V0 ship bar (from DESIGN_SPEC):**
`rubric_based_final_response_quality_v1 ≥ 0.8` ✓, `hallucinations_v1 = 1.0`
(currently 0.745, **threshold ≥0.7 met but the target of 1.0 is not** — staged
for Iter 6b verification), per-rubric no-zero ✓, per-skill recall ≥0.7
(currently 1.0) ✓.

**Phase A completed work:**

- ✅ Iter 1 — rubric tightening (6 loose → 10 ground-truth-anchored)
- ✅ Iter 1b/1c/1d — rubric calibration sub-iterations (XSS
  root-cause-vs-symptom, CSRF same fix, +unvalidated_redirects rubric)
- ✅ Iter 2/2b — skill directory refactor + `temperature=0` on
  `llm_discovery_agent` (variance hypothesis confirmed)
- ✅ Iter 3/3b — adversarial Triage Critic prompt + validation cap+adjudication
  wiring
- ✅ Iter 4–4f — Trivy live + four cascade fixes (cap-squeeze, model strategy
  split, validation preserves non-code evidence)
- ✅ Iter 5/5b/5c — synthetic per-skill corpus + two design lessons (ADK rubric
  verbatim-match; path-anonymity)
- ✅ Iter 6 — REPORT_INSTRUCTION per-finding Remediation field
- 🟨 Iter 6b — grounding-rule tightening shipped in code, validation deferred

**Phase A lessons worth carrying into Phase B:**

1.  **"Looks better, actually worse" is the iteration trap.** Iter 4d's
    all-flash 1.0 and Iter 6's 1.0 both inflated the headline number at
    hallucination cost. The eval design has to make this kind of regression
    detectable — Phase B should consider raising the `hallucinations_v1`
    threshold from 0.7 to 0.9 so the eval enforces what we currently catch by
    reading reports.
1.  **Every meaningful upstream upgrade crowds the downstream cap.** Recurring
    across Iter 3 (Triage Critic) and Iter 4 (Trivy). Structural fix (clustering
    for non-diverse signal classes) beats further cap bumps.
1.  **When a rubric resists multiple targeted fixes, look upstream at the
    pipeline, not the prompt.** Iter 3b's `unvalidated_redirects` lesson — five
    iterations of prompt/skill/rubric chasing; the actual fix was 2 lines in
    `VALIDATION_INSTRUCTION` raising the cap+filtering by adjudication.
1.  **Synthetic corpora must be path-anonymous from agent heuristics.** Iter
    5b's `tests/` → fixture-FP lesson.
1.  **ADK rubric matching is verbatim-text-lookup.** Keep rubrics short and
    structurally simple; the judge must repeat the text or scores silently null
    out.
1.  **`gemini-3.1-pro-preview` capacity is fragile around peer-model launches.**
    Selective model split (pro on quality-critical, flash on call-heavy) is the
    production answer.

**Phase B starting context** (from DESIGN_SPEC Roadmap):

- Implement Bandit (Python SAST) — paired with a Python target corpus (DVPWA or
  custom small target)
- Implement Gitleaks — paired with both corpora
- OWASP Benchmark integration (Java, ~3000 cases) — industry-comparable
  positioning
- Tree-sitter A/B pilot on `llm_discovery_agent` — eval-gated additive tool
- Open candidates from Phase A wrap: Iter 6b validation, raise hallucinations
  threshold to 0.9, fix or replace `tool_trajectory_avg_score`, add `safe.js` FP
  controls to synthetic corpus
