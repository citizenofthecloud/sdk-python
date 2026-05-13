# citizenofthecloud

Identity and authentication for autonomous AI agents. Python SDK.

**Prove who you are. Verify who you're talking to.**

## Install

This SDK is currently distributed directly from GitHub. The PyPI release is not yet caught up with the latest features (most recently: `register_agent()` and SDK-token auth). For now, install from GitHub:

```bash
git clone https://github.com/citizenofthecloud/sdk-python.git
pip install -e ./sdk-python
```

Or in a `requirements.txt`:

```
citizenofthecloud @ git+https://github.com/citizenofthecloud/sdk-python.git@main
```

Requires Python ≥ 3.9 and `cryptography` (installed automatically as a dependency).

## Quick Start

### Register a new agent (one-time setup)

Bootstrap a new Cloud Identity agent from a single function call. Generates a fresh Ed25519 keypair locally, posts the public key to the registry under your SDK token, and returns the `cloud_id` together with both keys. The private key never leaves your process — store it securely.

Get an SDK token from [citizenofthecloud.com/account](https://citizenofthecloud.com/account).

```python
import os
import citizenofthecloud as c

result = c.register_agent(
    sdk_token=os.environ["COTC_SDK_TOKEN"],
    name="My Research Bot",
    declared_purpose="Summarize papers and surface trends",
    autonomy_level="tool",
)

print(result["cloud_id"])
print(result["public_key"])
print(result["private_key"])   # STORE SECURELY — the server keeps only the public key
```

The returned `cloud_id` and `private_key` are the inputs to `CloudIdentity` for signing subsequent requests (see below).

### Sign outbound requests

```python
import os
from citizenofthecloud import CloudIdentity

me = CloudIdentity(
    cloud_id=os.environ["CLOUD_ID"],
    private_key=os.environ["CLOUD_PRIVATE_KEY"],
)

import requests
response = requests.post(
    "https://other-agent.com/api/task",
    json={"task": "analyze this"},
    headers=me.sign(),
)
```

### Verify incoming requests

```python
from citizenofthecloud import verify_agent

result = verify_agent(request.headers)

if result["verified"]:
    print(f"Verified: {result['agent']['name']}")
    print(f"Trust: {result['agent']['trust_score']}")
else:
    print(f"Rejected: {result['reason']}")
```

### Prove your own identity (challenge / respond)

```python
from citizenofthecloud import CloudIdentity

me = CloudIdentity(cloud_id="cc-...", private_key="-----BEGIN PRIVATE KEY-----\n...")
result = me.prove_identity()
print(result["verified"])  # True if the registry's challenge succeeds
```

### FastAPI integration

```python
from fastapi import FastAPI, Depends
from citizenofthecloud.fastapi import cloud_guard

app = FastAPI()

@app.post("/api/task")
async def task(agent=Depends(cloud_guard())):
    print(f"Request from {agent['name']}")
    return {"status": "accepted"}
```

### Generate keys without registering

If you want to manage registration yourself (or already have a keypair):

```python
from citizenofthecloud import generate_key_pair

keys = generate_key_pair()
print(keys["public_key"])   # submit during manual registration
print(keys["private_key"])  # keep secret
```

## Environment Variables

| Variable | Description |
|---|---|
| `CLOUD_ID` | Your agent's Cloud ID (e.g., `cc-7f3a9b2e-...`) |
| `CLOUD_PRIVATE_KEY` | Your agent's Ed25519 private key (PEM format) |
| `COTC_SDK_TOKEN` | Bootstrap SDK token (`cotc_sdk_*`) for `register_agent()`. Obtain from [citizenofthecloud.com/account](https://citizenofthecloud.com/account). |

## Links

- [Citizen of the Cloud](https://citizenofthecloud.com)
- [SDK Documentation](https://citizenofthecloud.com/docs)
- [Specification](https://citizenofthecloud.com/spec)
- [Account / SDK tokens](https://citizenofthecloud.com/account)

## License

MIT
