---
name: path-traversal
description: Searches for Path Traversal or Local File Inclusion (LFI) vulnerabilities where unvalidated user input controls file system paths.
---

# Objective

Identify Path Traversal (LFI/RFI) vulnerabilities. These occur when an
application uses unvalidated attacker-controlled input to construct a file path,
allowing an attacker to read or write sensitive files on the server (e.g.
`../../../../etc/passwd`).

## Methodology

You are acting as an expert application security reviewer hunting for CWE-22.

## Typical patterns to check

1.  Use `grep_code` to look for file system APIs:

- Node.js: `fs.readFile(`, `fs.writeFile(`, `res.sendFile(`, `path.join(`
- Python: `open(`, `os.path.join(`, `send_file(`

1.  Trace the variables passed into these functions to see if they originate
    from request parameters (e.g. `req.query.file`,
    `request.args.get('filename')`).

## True-positive signals

- Direct use of an HTTP parameter in `open(param)` or `fs.readFile(param)`.
- Use of `path.join(BASE_DIR, param)` without subsequent verification that the
  resolved path is still inside `BASE_DIR` (e.g. `../../` payloads can escape).
- Simple string replacements like `.replace('../', '')` which can be bypassed
  (e.g., `....//`).

## False-positive signals (do NOT flag)

- Strict validation against an allowlist of permitted filenames.
- Only the `basename` of the user input is used (e.g.,
  `os.path.basename(param)`), strictly removing traversal elements.
- The path resolves to a read-only static public directory, and the web server
  or framework natively prevents traversal escapes (e.g., Express `res.sendFile`
  is natively secure against escapes unless `root` is missing).

## Output: severity guidance

- **Critical** for arbitrary file writes or inclusions (LFI leading to RCE).
- **High** for arbitrary file reads (e.g., reading source code or config files).

## Output: CWE

- `CWE-22` (Improper Limitation of a Pathname to a Restricted Directory)

## Output: rule_id slug

- `ai.path-traversal-read` (reading files)
- `ai.path-traversal-write` (writing files)
