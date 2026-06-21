---
name: validate-path-traversal
description: Validates suspected path traversal vulnerabilities by synthesizing safe payloads and executing them inside the isolated sandbox.
when_to_apply: Enforced when a suspected path traversal / arbitrary file read (CWE-22) is triaged as a True Positive.
file_globs: ["*.js", "*.py", "*.java"]
---

# Path Traversal Validation Playbook

This playbook guides the Validation Agent on how to dynamically verify suspected
path traversal vulnerabilities safely within the isolated sandbox.

---

## 1. Adversarial Payload Synthesis

When user-supplied input is concatenated directly into a file system path
constructor (like `new File()` or `open()`), you must synthesize a safe exploit
verification payload.

### Dynamic Synthesis Rules

1.  **Traversing the Directory tree:** Synthesize a traversal path targeting a
    standard, predictable system file inside the sandbox runtime:

- **Alpine/Unix Standard file:** `../../../../etc/passwd`

1.  **Constructing the payload:**

- If the target code is:

    ```python
    with open("/var/app/uploads/" + user_file) as f:
    ```

    Synthesize the validation script calling this function with:
    `user_file = "../../../../etc/passwd"`

- Execute the function inside the sandbox.

---

## 2. Verification & Assertion Logic

After executing the sandbox using `execute_in_sandbox`, inspect the returned
dictionary:

- **Vulnerability Confirmed (TRUE_POSITIVE):**
    - If the `exit_code == 0` and the `stdout` contains the standard Alpine
      passwd file signature (e.g., `root:x:0:0:root:/root:/bin/ash` or
      `bin:x:1:1:bin:/bin:/sbin/nologin`), the path traversal is **100%
      validated**.
- **Vulnerability Refuted (FALSE_POSITIVE):**
    - If the file open fails with an error or is blocked by path normalization
      checks, mark as `validated: false`.

---

## 3. Remediation Standard

When proposing the remediation:

- **Require Path Normalization & Boundary Check:** Use the platform's native
  path resolution tool to resolve the absolute path of the base directory and
  the resolved target path, and verify that the target path starts with the base
  directory prefix:

    ```java
    Path basePath = Paths.get("/var/app/uploads/").toAbsolutePath();
    Path targetPath = basePath.resolve(param).normalize().toAbsolutePath();
    if (!targetPath.startsWith(basePath)) {
        throw new SecurityException("Invalid path access");
    }
    ```
