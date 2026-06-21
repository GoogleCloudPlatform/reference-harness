# Playbook: Directory Traversal & Path Traversal Detection

## CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### Threat Model & Vulnerability Shape

Path traversal occurs when an application takes user-supplied input and uses it
to construct a file path to read or write on the local disk without validating
that the path stays inside the intended directory root. Attackers can use
relative directory patterns (like `../../../../etc/passwd`) to escape the root
folder and read or overwrite sensitive host operating system files!

### Safe vs. Unsafe Code Shapes

#### Unsafe Shape (Unchecked Path Joins)

Joining user input directly to path names:

```javascript
const fs = require('fs');
const path = require('path');

app.get('/read_file', (req, res) => {
    const filename = req.query.file;
    // CRITICAL: path.join allows relative '..' directories!
    const targetPath = path.join(__dirname, 'public', filename);
    res.sendFile(targetPath);
});
```

#### Safe Shape (Strict Path resolution verification)

Verifying that the resolved path starts with the root base directory:

```javascript
const fs = require('fs');
const path = require('path');

app.get('/read_file', (req, res) => {
    const filename = req.query.file;
    const baseDir = path.join(__dirname, 'public');
    const targetPath = path.resolve(baseDir, filename);

    // SECURE: Ensure the resolved path strictly resides inside baseDir
    if (!targetPath.startsWith(baseDir)) {
        return res.status(403).send('Access Denied');
    }
    res.sendFile(targetPath);
});
```

### Security Audit Checklist for Discovery Agent

1.  **Audit File System IO calls:** Search for all filesystem reading or writing
    methods fanned out across Node, Python, or C++ code:

- Node: `fs.readFile`, `fs.createReadStream`, `res.sendFile`
- Python: `open()`, `send_from_directory` without validation
- C++: `std::ifstream`, `fopen`

1.  **Analyze Path constructs:** Check how the path is constructed:

- Is user-supplied input (URL query params, route segments, file uploads) joined
  directly using `path.join` or f-strings?
- Is there a check verifying that the resolved absolute path resides strictly
  inside the target root folder?

1.  **Check for relative sanitization failures:** Ensure that if the app
    replaces `../` with empty strings using regex, it is not bypassable (e.g.
    `....//` replacing once down to `../`!).
