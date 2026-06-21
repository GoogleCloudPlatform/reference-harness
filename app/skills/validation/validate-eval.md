---
name: validate-eval
description: Validates suspected dynamic code injection (eval/Function) vulnerabilities by synthesizing safe payloads and executing them inside the isolated sandbox.
when_to_apply: Enforced when a suspected dynamic code injection (CWE-95 / CWE-94) is triaged as a True Positive.
file_globs: ["*.js", "*.py"]
---

# Dynamic Code Injection Validation Playbook

This playbook guides the Validation Agent on how to dynamically verify suspected
server-side code injection vulnerabilities safely within the isolated sandbox.

---

## 1. Adversarial Payload Synthesis

When user-supplied data reaches a dynamic execution sink (like Javascript
`eval()`, `Function()`, `setTimeout()` or Python `eval()`, `exec()`), you must
synthesize a safe exploit verification payload.

### Dynamic Synthesis Rules

1.  **Safe Injector Payloads:** Synthesize an input that executes a benign
    calculation or returns a highly unique system string identifier:

- **Benchmarking Math:** `1 + 2`
- **Identifier Payload:** `"VULN_EVAL_RCE"`

1.  **Constructing the payload:**

- If the target Python code is:

    ```python
    res = eval(request.args.get("expr"))
    ```

    Synthesize the validation script calling this function with:
    `expr = "'VULN_EVAL_RCE'"`

- If the target JavaScript code is:

    ```javascript
    let res = eval(req.body.math);
    ```

    Synthesize the validation script calling this function with:
    `math = "1 + 2"` (asserting `res === 3`).

---

## 2. Verification & Assertion Logic

After executing the sandbox using `execute_in_sandbox`, inspect the returned
dictionary:

- **Vulnerability Confirmed (TRUE_POSITIVE):**
    - If the output or return value matches the benchmark math result (e.g. `3`)
      or contains the identifier string **`VULN_EVAL_RCE`**, the vulnerability
      is **100% validated**.
- **Vulnerability Refuted (FALSE_POSITIVE):**
    - If the execution fails or throws an error indicating that the dynamic
      input was rejected, sanitized, or typecast, mark the finding as
      `validated: false`.

---

## 3. Remediation Standard

When proposing the remediation:

- **JavaScript:** Require replacing `eval()` with safe parsing abstractions
  (like `JSON.parse()`) or contextual execution blocks (like
  `vm.runInNewContext()` with zero globals if sandboxing is required).
- **Python:** Require replacing `eval()` with `ast.literal_eval()` to safely
  parse literals (strings, numbers, tuples, lists, dicts) without executing
  arbitrary code.
