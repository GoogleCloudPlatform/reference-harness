---
name: cmd-injection
description: Searches for OS Command Injection vulnerabilities where untrusted user input is passed into system shells or command executors.
---

# Objective

Identify OS Command Injection vulnerabilities. These occur when an application
passes unsafe user-supplied data (forms, cookies, HTTP headers) to a system
shell. In this attack, the attacker's input is executed as operating system
commands by the underlying host.

## Methodology

You are acting as an expert application security reviewer hunting for CWE-78.

## Typical patterns to check

1.  Use `grep_code` to look for OS execution functions:

- Node.js: `exec(`, `spawn(`, `execSync(`, `execFile(`
- Python: `os.system(`, `subprocess.Popen(`, `subprocess.run(`, `os.popen(`
- PHP/Ruby/Other: `` ` ``, `system(`, `passthru(`

1.  Once an execution sink is found, trace the arguments backwards using
    `read_code_window` and `find_references` to see if they derive from HTTP
    requests (e.g. `req.body`, `request.GET`).

## True-positive signals

- A dynamic string containing HTTP request data is passed directly into a shell
  execution function (e.g., `shell=True` in Python, or `exec()` in Node).
- String concatenation or template literals are used to build OS commands using
  user input.

## False-positive signals (do NOT flag)

- `execFile` or `subprocess.run(..., shell=False)` where user input is passed
  safely as array arguments (parameters), preventing shell metacharacter
  injection.
- Execution parameters that are strictly hardcoded constants or
  server-controlled configuration values.
- Integer or Enum casting: The user input is strictly parsed to an integer
  before being used in the command.

## Output: severity guidance

- **Critical** for any exploitable command injection (allows arbitrary RCE on
  the host).
- **High** for blind command injection or limited command injection (e.g.,
  attacker can inject arguments but not arbitrary commands).

## Output: CWE

- `CWE-78` (Improper Neutralization of Special Elements used in an OS Command)

## Output: rule_id slug

- `ai.os-cmd-injection` (arbitrary command execution)
- `ai.argument-injection` (injection into arguments of a secure executor)
