---
name: validate-command-injection
description: Validates suspected command injection vulnerabilities by synthesizing safe payloads and executing them inside the isolated sandbox.
when_to_apply: Enforced when a suspected command injection vulnerability (CWE-78) is triaged as a True Positive.
file_globs: ["*.js", "*.py", "*.sh"]
---

# Command Injection Validation Playbook

This playbook guides the Validation Agent on how to dynamically verify suspected
command injection vulnerabilities safely within the isolated sandbox.

---

## 1. Adversarial Payload Synthesis

When a command injection vulnerability is suspected (e.g. input interpolated
inside a shell executor like `subprocess.check_output(..., shell=True)` in
Python or `child_process.exec()` in Node), you must synthesize a safe exploit
verification payload.

### Dynamic Synthesis Rules

1.  **Safe Injector Suffixes:** Append a harmless validation command that
    outputs a highly unique string identifier, separated by standard shell
    delimiters:

- **Unix Delimiters:** `;`, `&`, `|`, `\n`
- **Identifier Payload:** `echo VULN_CMD_INJECTION`

1.  **Constructing the payload:**

- If the target code is:

    ```python
    subprocess.check_output(f"echo hi {user_input}", shell=True)
    ```

- Synthesize the validation script calling this function with:
  `user_input = "; echo VULN_CMD_INJECTION"`
- Execute the function inside the sandbox.

---

## 2. Verification & Assertion Logic

After executing the sandbox using `execute_in_sandbox`, inspect the returned
dictionary:

- **Vulnerability Confirmed (TRUE_POSITIVE):** If the `exit_code == 0` and the
  `stdout` (or `stderr`) contains the unique string **`VULN_CMD_INJECTION`**,
  the vulnerability is **100% validated**.
- **Vulnerability Refuted (FALSE_POSITIVE):** If the execution exits cleanly but
  the identifier string **`VULN_CMD_INJECTION`** is missing from the output, the
  input parameter is successfully sanitized or restricted by the surrounding
  code. Mark as `validated: false`.

---

## 3. Remediation Standard

When proposing the remediation for a validated command injection:

- **Strictly reject** string concatenations or f-string interpolations in shell
  executors.
- **Require array-based parameter execution** with shell execution disabled:
    - **Python:** `subprocess.run(["echo", "hi", user_input], shell=False)`
    - **Node.js:** `child_process.execFile("echo", ["hi", user_input])`
