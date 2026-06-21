---
name: eval-or-function-injection
description: Detects server-side code injection via eval(), Function(), exec(), or similar interpreters fed user input
when_to_apply: Any server-side codebase. JS/Python especially common.
file_globs: **/routes/**, **/controllers/**, **/handlers/**, **/services/**, **/*.js, **/*.ts, **/*.py
---

# Eval / Function Injection: Detection Procedure

## What this is

User-controlled input is passed to a dynamic-code interpreter (`eval`,
`Function`, Python `exec`/`eval`, Ruby `eval`), letting an attacker execute
arbitrary server-side code. OWASP A1 / CWE-94, CWE-95.

## Where to look

1.  Route handlers that do "calculation," "expression evaluation," "formula
    parsing," or "dynamic config."
1.  Anywhere the codebase wants to be "flexible" — config parsers, templating
    shortcuts, REPL endpoints.

## How to find it

1.  `grep_code` for the sinks:

- `\beval\s*\(`
- `new\s+Function\s*\(`
- `\bFunction\s*\(['"]` (constructor invocation)
- `\bexec\s*\(` (Python)
- `\bcompile\s*\(.*,\s*['"]exec['"]\)` (Python)
- `setTimeout\s*\(\s*['"]` (string-form setTimeout is also eval)
- `setInterval\s*\(\s*['"]`

1.  For each hit, `read_code_window` and check whether the argument flows from
    `req.body`, `req.query`, `req.params`, `request.form`, `request.json`, etc.
1.  Trace inputs one level back if the value is from a variable.

## True-positive signals

- `eval(req.body.something)` or any direct request data reaching `eval` /
  `Function` / `exec`.
- Code comments like "// allow user to define formulas" near an `eval`.
- A "calculator" / "formula" / "expression" route that takes user text and
  evaluates it.

## False-positive signals (do NOT flag)

- `eval` is called on a hardcoded string constant.
- `Function(...)` is used as a type check or with a fixed string body (no user
  input).
- Test/spec files using `eval` to set up test fixtures.

## Output: severity guidance

- **Critical** almost always — server-side RCE is the worst outcome.
- Drop to **High** only if the route requires admin auth AND there's a sanitizer
  in between (still report it).

## Output: CWE

- `CWE-94` (Improper Control of Generation of Code)
- `CWE-95` (Improper Neutralization of Directives in Dynamically Evaluated Code)

## Output: rule_id slug

- `ai.server-side-js-injection` (Node)
- `ai.python-eval-injection` (Python)
- `ai.dynamic-code-execution` (generic)
