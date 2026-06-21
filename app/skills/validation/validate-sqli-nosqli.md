---
name: validate-sqli-nosqli
description: Validates suspected SQL and NoSQL database injection vulnerabilities by synthesizing safe payloads and executing them inside the isolated sandbox.
when_to_apply: Enforced when a suspected SQL/NoSQL database injection (CWE-89 / CWE-943) is triaged as a True Positive.
file_globs: ["*.js", "*.py", "*.java"]
---

# SQL & NoSQL Injection Validation Playbook

This playbook guides the Validation Agent on how to dynamically verify suspected
database injection vulnerabilities safely within the isolated sandbox.

---

## 1. Adversarial Payload Synthesis

When user-supplied data is concatenated directly into raw SQL queries or dynamic
NoSQL expressions (like MongoDB `$where` clauses), you must synthesize a safe
exploit verification payload.

### Dynamic Synthesis Rules

1.  **SQL Injection (concatenation):** Synthesize a standard SQL string escape
    payload that alters the query logic safely:

- **SQL Payload:** `' OR '1'='1`
- **Verification:** If the returned database results list includes all rows, or
  the query logic succeeds regardless of the first argument, the SQLi is
  validated.

1.  **NoSQL/MongoDB Injection (like `$where`):**

- If the target code is:

    ```javascript
    db.collection.find({ $where: "this.userId == " + user_input })
    ```

- Synthesize the validation script calling this function with:
  `user_input = "1 || true"`
- **Verification:** If the output database document list returns all documents,
  the NoSQLi is validated.

---

## 2. Verification & Assertion Logic

After executing the sandbox using `execute_in_sandbox`, inspect the returned
dictionary:

- **Vulnerability Confirmed (TRUE_POSITIVE):**
    - If the database query returns a complete dump of mock rows (due to
      `'1'='1` or `true` bypasses) or throws a database syntax error confirming
      unescaped string inputs reached the engine, the vulnerability is **100%
      validated**.
- **Vulnerability Refuted (FALSE_POSITIVE):**
    - If the query execution fails or is blocked by parameterization or strict
      input cast validations, mark as `validated: false`.

---

## 3. Remediation Standard

When proposing the remediation:

- **SQL Injection:** **Always require parameterized queries (Prepared
  Statements)**. Never accept sanitization or escaping as a primary fix.
- **NoSQL Injection:** Reject the usage of dynamic code execution clauses (like
  `$where`). Require using safe native MongoDB operators (like `$eq`, `$gt`).
