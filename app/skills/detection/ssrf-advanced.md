# Playbook: Server-Side Request Forgery (SSRF) Detection

## CWE-918: Server-Side Request Forgery (SSRF)

### Threat Model & Vulnerability Shape

SSRF occurs when a backend application takes user-supplied URL inputs and
fetches content from that URL using server-side HTTP libraries (like `axios`,
`request`, `urllib`) without restricting the target destinations. Attackers can
supply local or private IP addresses (e.g., local loopback
`http://127.0.0.1:27017`, or AWS metadata services `http://169.254.169.254`) to
query internal services or steal cloud credentials!

### Safe vs. Unsafe Code Shapes

#### Unsafe Shape (Unchecked URL Fetch)

Fetching external URLs directly without ip/host validation:

```python
import urllib.request
from flask import request

@app.route("/fetch_metadata")
def fetch_metadata():
    url = request.args.get("url")
    # CRITICAL: urllib fetches arbitrary hosts including local loopback and AWS metadata IPs!
    response = urllib.request.urlopen(url)
    return response.read()
```

#### Safe Shape (Strict Host & Private IP restrictions)

Resolving the target host IP and enforcing strict allow-list/deny-list checks:

```python
import socket
import urllib.parse
import urllib.request
from flask import request

@app.route("/fetch_metadata")
def fetch_metadata():
    url = request.args.get("url")
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname

    # SECURE: Resolve host IP and block private/local IP ranges!
    try:
        ip = socket.gethostbyname(host)
        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip == "169.254.169.254":
            return "Access Denied", 403

        response = urllib.request.urlopen(url)
        return response.read()
    except Exception:
        return "Access Denied", 403
```

### Security Audit Checklist for Discovery Agent

1.  **Identify Outbound HTTP clients:** Search for all server-side HTTP client
    utilities:

- Node: `axios`, `request`, `fetch`, `needle`, `http.get`
- Python: `urllib.request`, `requests.get`, `requests.post`
- C++: `libcurl`

1.  **Trace URL source origins:** For every HTTP client call, trace the `url`
    parameter:

- Is the URL sourced directly from a public HTTP query parameter, request body,
  or API payload?
- Is there a strict validation check (regex or hostname allow-list) verifying the
  destination?

1.  **Check DNS Rebinding defenses:** Verify if the application resolves the IP
    address first and checks it, or if it is subject to DNS rebinding attacks
    (e.g., returning a public IP for the first check, and a local private IP for
    the actual fetch!).
