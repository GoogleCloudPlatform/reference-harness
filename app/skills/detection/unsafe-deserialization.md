# Playbook: Unsafe Deserialization Detection

## CWE-502: Deserialization of Untrusted Data

### Threat Model & Vulnerability Shape

Unsafe deserialization occurs when an application deserializes untrusted
user-supplied byte streams, JSON, or serialized object strings without
validating their structure. Attackers can craft serialized byte streams that,
upon instantiation/unpickling, dynamically execute arbitrary OS commands or
commands fanned out by embedded callback parameters, leading to instant RCE!

### Safe vs. Unsafe Code Shapes

#### Unsafe Python Shape (pickle.loads)

Unpickling untrusted user bytes directly:

```python
import pickle
from flask import request

@app.route("/load_session")
def load_session():
    data = base64.b64decode(request.args.get("session"))
    # CRITICAL: pickle.loads executes arbitrary code embedded in bytes!
    session = pickle.loads(data)
    return "Session loaded"
```

#### Safe Python Shape (json.loads)

Using standard, non-executable serialization payloads (like JSON):

```python
import json
from flask import request

@app.route("/load_session")
def load_session():
    data = base64.b64decode(request.args.get("session"))
    # SECURE: json.loads only parses primitives, never instantiates executable objects
    session = json.loads(data)
    return "Session loaded"
```

### Security Audit Checklist for Discovery Agent

1.  **Audit Python Deserializers:** Search for dangerous Python unpicklers:

- `pickle.loads()`
- `pickle.load()`
- `yaml.load()` without `Loader=yaml.SafeLoader` (ruamel/pyyaml)

1.  **Audit JavaScript / Node Deserializers:** Search for dangerous JS
    serializers:

- `node-serialize` package unpicklers: `unserialize()`
- `serialize-javascript` package unpicklers

1.  **Audit Java Deserializers:** Search for raw
    `ObjectInputStream.readObject()` calls processing untrusted servlet inputs.
1.  **Check validation before read:** Ensure that if deserialization _is_
    required, the bytes stream is validated against a strict HMAC signature to
    prevent tampering.
