# Playbook: Race Condition & TOCTOU Detection

## CWE-367: Time-of-Check to Time-of-Use (TOCTOU) Race Condition

### Threat Model & Vulnerability Shape

A TOCTOU race condition occurs when a security-critical check is performed on a
resource (such as verifying permissions on a file), but the resource is modified
by a concurrent thread or process _after_ the check is completed but _before_
the resource is actually used. An attacker can swap the target resource (e.g.
swapping a validated temp file with a symlink to `/etc/passwd`) in that tiny
time gap, tricking the privileged process into overwriting sensitive files.

### Safe vs. Unsafe Code Shapes

#### Unsafe Shape (access() followed by open())

Performing check and use as two separate non-atomic path operations:

```c
void write_config(char *path, char *data) {
    // CRITICAL: check file ownership using path
    if (access(path, W_OK) == 0) {
        // TOCTOU GAP: Attacker swaps 'path' with symlink here!
        FILE *f = fopen(path, "w");
        fputs(data, f);
        fclose(f);
    }
}
```

#### Safe Shape (File descriptor atomic checking)

Checking permissions directly on the opened file descriptor (atomic):

```c
void write_config(char *path, char *data) {
    // SECURE: Open first, then check permissions on the atomic file descriptor
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) {
        // File opened safely; write using fd
        write(fd, data, strlen(data));
        close(fd);
    }
}
```

### Security Audit Checklist for Discovery Agent

1.  **Audit File Path logic:** Search for legacy path checker pairs:

- `access()` followed by `open()` or `fopen()`
- `stat()` followed by `chmod()` or `chown()`

1.  **Audit Multi-threaded state access:** Look for shared global or heap
    variables inside concurrent execution scopes (`pthread_create`,
    std::thread):

- Is access to the shared state locked using mutexes (`std::mutex`,
  `pthread_mutex_t`) or atomic operations?
- Identify critical sections where locks are released too early, creating a race
  gap.

1.  **Check Directory tree traversal races:** Ensure directories are opened
    using `openat()` and relative file descriptors to prevent path swapping
    symlink attacks.
