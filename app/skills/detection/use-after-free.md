# Playbook: Use-After-Free (UAF) Detection (C/C++)

## CWE-416: Use After Free

### Threat Model & Vulnerability Shape

Use-after-free occurs when an application continues to use or reference a memory
pointer after the memory it points to has been explicitly freed (using `free()`
or `delete`). Attackers can manipulate the memory heap layout (Heap Feng Shui)
to reclaim the freed slot, placing their own malicious object structures there,
which the dangling pointer then executes, leading to RCE.

### Safe vs. Unsafe Code Shapes

#### Unsafe Shape (Dangling Pointer)

Using a pointer after free without nulling:

```c
void process_session() {
    UserSession *session = (UserSession *)malloc(sizeof(UserSession));
    // ...
    free(session);
    // CRITICAL: Dangling pointer! session is still referenced here.
    if (session->is_admin) {
        execute_admin_action();
    }
}
```

#### Safe Shape (Nulling Pointer after Free)

Nullifying the pointer immediately after free:

```c
void process_session() {
    UserSession *session = (UserSession *)malloc(sizeof(UserSession));
    // ...
    free(session);
    session = NULL; // SECURE: Prevents any dangling references!
}
```

### Security Audit Checklist for Discovery Agent

1.  **Trace free() and delete calls:** For every memory deallocation block,
    audit the surrounding scope:

- Is the pointer nullified immediately after `free(ptr)` or `delete ptr`?
- Search for any references, pointer arithmetic, or variable assignments using
  `ptr` after the deallocation line.

1.  **Trace Pointer Aliasing:** Look for pointer aliases (e.g.,
    `UserSession *alias = session;`). If `session` is freed, does `alias` still
    get dereferenced?
1.  **Audit Double Free:** Search for multiple sequential `free()` calls on the
    same pointer along different execution paths, especially in error handling
    blocks (`goto cleanup;`).
