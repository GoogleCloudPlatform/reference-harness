# Playbook: JWT Authentication Validation Bypass Detection

## CWE-347: Improper Verification of Cryptographic Signature

### Threat Model & Vulnerability Shape

JSON Web Tokens (JWT) are widely used for session management and API
authentication. Cryptographic signatures guarantee token integrity.
Vulnerabilities happen when the backend:

1.  **Accepts the "none" algorithm:** Attackers can modify their payload (e.g.
    changing `"user": "guest"` to `"user": "admin"`) and set the JWT algorithm
    header `"alg": "none"`, completely bypassing signature checks!
1.  **Performs Key Confusion:** If a codebase uses asymmetric RS256
    (public/private key pair) to sign tokens, but the verification check takes
    the public key as a symmetric HS256 key, attackers can sign the token using
    the public key, bypassing signature verifications!

### Safe vs. Unsafe Code Shapes

#### Unsafe Shape (None Algorithm allowed)

Decoding without algorithm restrictions:

```javascript
const jwt = require('jsonwebtoken');

app.get('/admin', (req, res) => {
    const token = req.headers['authorization'];
    // CRITICAL: does not specify alg restrictions! Accepts alg: 'none'.
    const decoded = jwt.decode(token);
    if (decoded.role === 'admin') {
        res.send('Welcome admin');
    }
});
```

#### Safe Shape (Strict Algorithm Constraints)

Decoding with explicit algorithm allow-list:

```javascript
const jwt = require('jsonwebtoken');

app.get('/admin', (req, res) => {
    const token = req.headers['authorization'];
    // SECURE: verify signature using secret and enforce strict algorithm allow-lists
    jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] }, (err, decoded) => {
        if (err) return res.sendStatus(403);
        if (decoded.role === 'admin') {
            res.send('Welcome admin');
        }
    });
});
```

### Security Audit Checklist for Discovery Agent

1.  **Audit JWT verification methods:** Search for raw decode or verification
    calls:

- `jwt.decode()` (always insecure for authentication because it performs no
  signature verification!).
- `jwt.verify()` or `PyJWT.decode()` without specifying `{ algorithms: [...] }`
  or `algorithms=[...]`.

1.  **Check Public key confusion:** Identify if public key variables (which are
    publicly accessible!) are accidentally fed into symmetric key verify
    checkers as secrets.
1.  **Check Expiration validation:** Verify if the token expiration (`exp`
    claim) check is explicitly performed or disabled (`ignoreExpiration: true`).
