# citizenofthecloud

Identity and authentication SDK for autonomous AI agents. Part of the [Citizen of the Cloud](https://citizenofthecloud.com) registry.

Prove who you are. Verify who you're talking to.

## Install

```bash
pip install citizenofthecloud
```

Or install from source:

```bash
git clone https://github.com/citizenofthecloud/sdk-python.git
cd sdk-python
pip install .
```

## Quick Start

### Generate Keys

```python
from citizenofthecloud import generate_key_pair

keys = generate_key_pair()
print(keys['public_key'])   # Submit this during registration
# Keep keys['private_key'] secret — this is your agent's signing key
```

### Sign Outbound Requests

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

### Verify Incoming Requests

```python
from citizenofthecloud import verify_agent

result = verify_agent(request.headers)

if result["verified"]:
    print(f"Verified: {result['agent']['name']}")
    print(f"Trust: {result['agent']['trust_score']}")
else:
    print(f"Rejected: {result['reason']}")
```

### FastAPI Integration

```python
from fastapi import FastAPI, Request, HTTPException
from citizenofthecloud import verify_agent, TrustPolicy

app = FastAPI()

policy = TrustPolicy(
    require_covenant=True,
    minimum_trust_score=0.5,
    allowed_autonomy_levels=["agent", "assistant"],
)

@app.post("/api/task")
async def handle_task(request: Request):
    result = verify_agent(dict(request.headers), policy=policy)
    if not result["verified"]:
        raise HTTPException(status_code=403, detail=result["reason"])

    agent = result["agent"]
    return {"message": f"Hello {agent['name']}, task accepted."}
```

### Trust Policy

Control which agents can access your endpoints:

```python
from citizenofthecloud import TrustPolicy, verify_agent

policy = TrustPolicy(
    minimum_trust_score=0.6,       # Require established trust
    require_covenant=True,          # Must have signed the covenant
    allowed_autonomy_levels=["agent", "assistant"],  # No self-directing
    blocked_agents=["cc-..."],      # Block specific agents
    max_age=300,                    # Signatures valid for 5 minutes
)

result = verify_agent(headers, policy=policy)
```

### Request-Bound Signatures

For higher security, bind signatures to a specific request:

```python
# Sender: sign with request context
headers = identity.sign_request(
    url="https://api.example.com/data",
    method="POST",
    body='{"query": "test"}',
)

# Receiver: verify with request context
from citizenofthecloud import verify_request

result = verify_request(
    headers=request.headers,
    url=str(request.url),
    method=request.method,
    body=await request.body(),
)
```

### Fetch with Automatic Signing

```python
from citizenofthecloud import cloud_fetch

response = cloud_fetch(
    identity=me,
    url="https://other-agent.com/api/data",
    method="POST",
    body='{"query": "latest results"}',
)
print(response["status"])  # 200
print(response["body"])    # Parsed JSON response
```

## How It Works

1. **Registration**: Your agent registers at [citizenofthecloud.com](https://citizenofthecloud.com/register) with an Ed25519 public key
2. **Signing**: Outbound requests include `X-Cloud-ID`, `X-Cloud-Timestamp`, and `X-Cloud-Signature` headers
3. **Verification**: The receiving agent checks the signature against the public key in the registry
4. **Trust**: The registry returns the agent's trust score, covenant status, and profile alongside verification

Signatures use Ed25519 over `{cloud_id}:{timestamp}`. Request-bound signatures extend this to include method, URL, and body hash.

## Examples

See the [`examples/`](examples/) directory:

- `poc.py` — Two-agent proof of concept: register, sign, verify, and test failure cases
- `test-sdk-verification.py` — Full verification test suite including Trust Policy enforcement

## API Reference

| Function | Purpose |
|---|---|
| `generate_key_pair()` | Generate Ed25519 key pair |
| `CloudIdentity(cloud_id, private_key)` | Create signing identity |
| `identity.sign()` | Sign outbound request |
| `identity.sign_request(url, method, body)` | Sign with request binding |
| `identity.get_passport()` | Fetch own passport |
| `verify_agent(headers, policy=)` | Verify incoming request |
| `verify_request(headers, url, method, body)` | Verify request-bound signature |
| `cloud_fetch(identity, url, method, body)` | HTTP request with auto-signing |
| `TrustPolicy(...)` | Reusable verification rules |
| `clear_cache()` | Clear verification cache |

## Requirements

- Python 3.9+
- `cryptography>=41.0` (Ed25519 support)

## Links

- **Registry**: [citizenofthecloud.com](https://citizenofthecloud.com)
- **Spec**: [citizenofthecloud.com/spec](https://citizenofthecloud.com/spec)
- **Docs**: [citizenofthecloud.com/docs](https://citizenofthecloud.com/docs)
- **Governance**: [citizenofthecloud.com/governance](https://citizenofthecloud.com/governance)
- **JavaScript SDK**: [github.com/citizenofthecloud/sdk-js](https://github.com/citizenofthecloud/sdk-js)
- **Go SDK**: [github.com/citizenofthecloud/sdk-go](https://github.com/citizenofthecloud/sdk-go)
- **Rust SDK**: [github.com/citizenofthecloud/sdk-rust](https://github.com/citizenofthecloud/sdk-rust)

## License

MIT
