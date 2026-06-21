# Playbook: Buffer Overflow Detection (C/C++)

## CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')

### Threat Model & Vulnerability Shape

A buffer overflow occurs when C/C++ code copies user-supplied input into a
fixed-size memory buffer (on the Stack or Heap) without verifying that the input
size is strictly smaller than the buffer capacity. This allows attackers to
overwrite adjacent memory, leading to arbitrary Remote Code Execution (RCE) or
denial of service (crashes).

### Safe vs. Unsafe Code Shapes

#### Unsafe Shape (strcpy, strcat, sprintf)

Unsafe copying of unbounded strings:

```c
void handle_connection(char *user_input) {
    char buffer[128];
    // CRITICAL: strcpy does not check target buffer capacity!
    strcpy(buffer, user_input);
}
```

#### Safe Shape (strncpy, snprintf, bounds checks)

Safe bounds-checked string copying:

```c
void handle_connection(char *user_input) {
    char buffer[128];
    // SECURE: strncpy limits copy length to buffer size minus 1
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0'; // Ensure null termination
}
```

### Security Audit Checklist for Discovery Agent

1.  **Scan for Unsafe Sinks:** Search for all occurrences of legacy, unsafe
    string manipulation functions:

- `strcpy`
- `strcat`
- `sprintf`
- `gets`
- `scanf`

1.  **Analyze Buffer Boundaries:** For every buffer declaration (e.g.,
    `char buf[N]`), trace its data flow:

- Is the source data supplied from an external input boundary (like a POSIX
  socket, file read, environment variable, or UI text field)?
- Is the length of the input validated against `N` _before_ it is copied?

1.  **Check Fuzzing/Copy offsets:** Trace `memcpy` and `memmove` offsets. Ensure
    that the size parameter `n` is derived safely, and does not allow
    negative/overflow values:

- `memcpy(dest, src, n)` -> Is `n` checked to prevent out-of-bounds reads or
  writes?
