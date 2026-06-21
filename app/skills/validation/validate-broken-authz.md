---
name: validate-broken-authz
description: Validates suspected Broken Authorization and privilege escalation vulnerabilities by executing them inside the isolated sandbox.
when_to_apply: Enforced when a suspected Broken Authorization/AuthZ check (CWE-285 / CWE-862) is triaged as a True Positive.
file_globs: ["*.js", "*.py"]
---

# Broken Authorization (AuthZ) Validation Playbook

This playbook guides the Validation Agent on how to dynamically verify suspected
Broken Authorization vulnerabilities safely within the isolated sandbox.

---

## 1. Adversarial Payload Synthesis

Broken Authorization occurs when restricted or administrative actions can be
successfully executed by sessions lacking the necessary high-privilege roles
(privilege escalation).

### Dynamic Synthesis Rules

1.  **Simulating Low-Privilege Request:** To dynamically prove broken
    authorization, you must execute the administrative route handler while
    explicitly passing a session representing a standard, non-privileged user
    account.
1.  **Constructing the payload:**

- If the target administrative endpoint is:

    ```javascript
    app.post("/admin/delete-user", (req, res) => {
        db.deleteUser(req.body.id);
        res.send("Deleted");
    });
    ```

- Synthesize a validation script:
    1.  Mock a session representing a standard guest/user
        (`req.session.role = "user"` or `req.session.isAdmin = false`).
    1.  Call the handler requesting the deletion of a mock record ID.
    1.  Execute inside the sandbox.

---

## 2. Verification & Assertion Logic

After executing the sandbox using `execute_in_sandbox`, inspect the returned
dictionary:

- **Vulnerability Confirmed (TRUE_POSITIVE):**
    - If the handler executes the action successfully and returns a success
      status, the Broken Authorization is **100% validated** (proving missing
      role-validation checks).
- **Vulnerability Refuted (FALSE_POSITIVE):**
    - If the handler throws a `403 Forbidden` or `401 Unauthorized` indicating
      that the low-privilege role was rejected before execution, mark as
      `validated: false`.

---

## 3. Remediation Standard

When proposing the remediation:

- **Strict Role-Based Access Controls (RBAC):** Require registering standard
  authorization middleware (e.g., checking `isAdmin` flag or specific role
  properties) on all administrative and sensitive resource route paths.
