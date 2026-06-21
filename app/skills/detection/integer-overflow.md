# Playbook: Integer Overflow Detection (C/C++)

## CWE-190: Integer Overflow or Wraparound

### Threat Model & Vulnerability Shape

An integer overflow occurs when an arithmetic operation attempts to create a
numeric value that is outside the range that can be represented by the integer
type. This causes a "wraparound" (e.g., an extremely large unsigned integer
addition wrapping around to a tiny positive number). If this wrapped value is
passed as a memory allocation size parameter (e.g., `malloc(size)`), it
allocates a tiny buffer, but the subsequent copy loop writes the full data,
resulting in a Heap buffer overflow!

### Safe vs. Unsafe Code Shapes

#### Unsafe Shape (Overflow in malloc size)

Arithmetic multiplication without overflow check:

```c
void allocate_items(int count) {
    // CRITICAL: if count is massive, count * sizeof(Item) wraps around to a tiny positive number!
    int size = count * sizeof(Item);
    Item *list = (Item *)malloc(size); // Tiny buffer allocated!
    for (int i = 0; i < count; i++) {
        list[i] = get_item_data(); // Heap buffer overflow!
    }
}
```

#### Safe Shape (Overflow Bounds Checking)

Verifying arithmetic boundaries before allocation:

```c
void allocate_items(int count) {
    if (count <= 0 || count > MAX_ITEMS) {
        return; // SECURE: Restrict counts
    }
    // SECURE: check for multiplication overflow before malloc
    if (count > INT_MAX / sizeof(Item)) {
        return; // Arithmetic bounds error!
    }
    int size = count * sizeof(Item);
    Item *list = (Item *)malloc(size);
    // ...
}
```

### Security Audit Checklist for Discovery Agent

1.  **Audit Memory Allocation size parameters:** Search for all allocations
    (`malloc`, `calloc`, `realloc`, `new[]`) fanned out in C++ code:

- Is the size argument derived from arithmetic calculations (`count * size`,
  `len1 + len2`)?
- Trace if those variables are unchecked or originate from user inputs/socket
  buffers.

1.  **Audit Sign extension casting:** Check for casts between signed and
    unsigned integers (e.g., casting a signed `short` to an unsigned `int`). If
    the signed integer is negative, it maps to a massive unsigned value!
1.  **Trace width conversions:** Check for casting a 64-bit integer (`uint64_t`)
    down to a 32-bit integer (`uint32_t`), which drops the upper bits and wraps
    the value around.
