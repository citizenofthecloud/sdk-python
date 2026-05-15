# citizenofthecloud

Identity and authentication for autonomous AI agents. Python SDK.

**Prove who you are. Verify who you're talking to.**

The Citizen of the Cloud SDK exposes **17 tools** across the agent identity protocol — registration, signing, verification, the challenge/respond loop, registry queries, and a FastAPI route-guard middleware.

---

## Install

```bash
# From GitHub (latest — recommended while PyPI catches up)
pip install git+https://github.com/citizenofthecloud/sdk-python.git

# With FastAPI route-guard extras
pip install "citizenofthecloud[fastapi] @ git+https://github.com/citizenofthecloud/sdk-python.git"
```

Requires Python ≥ 3.9 and `cryptography` (installed automatically).

---

## The 17-tool surface

| # | Tool | API | Purpose |
|---|---|---|---|
| 1 | lookup-agent | `lookup_agent(registry_url, cloud_id)` | Read another agent's public passport |
| 2 | get-server-identity | `identity.get_passport()` | Fetch your own passport |
| 3 | list-directory | `list_directory(registry_url)` | Browse the public agent directory |
| 4 | governance-feed | `get_governance_feed(registry_url)` | Read recent registry events |
| 5 | verify-agent | `verify_agent(headers, policy=...)` | Verify signed headers (simple) |
| 6 | verify-request | `verify_request(headers, url, method, body, policy=...)` | Verify request-bound signature |
| 7 | request-challenge | `request_challenge(registry_url, cloud_id)` | Ask the registry for a nonce |
| 8 | respond-to-challenge | `submit_challenge_response(...)` | Submit a signed nonce |
| 9 | prove-identity | `identity.prove_identity()` | Full challenge/sign/respond loop |
| 10 | sign-headers | `identity.sign()` | Produce timestamp-bound headers |
| 11 | sign-request | `identity.sign_request(url, method, body)` | Produce request-bound headers |
| 12 | cloud-fetch | `cloud_fetch(identity, url, method, body)` | Auto-signed HTTP request |
| 13 | generate-keypair | `generate_key_pair()` | Make a fresh Ed25519 keypair |
| 14 | trust-policy | `TrustPolicy(...)` | Reusable verification rules |
| 15 | clear-cache | `clear_cache()` | Clear the verification cache |
| 16 | http-middleware | `CloudGuard` / `cloud_guard` (from `citizenofthecloud.fastapi`) | FastAPI route guard |
| 17 | register-agent | `register_agent(...)` | Programmatic agent registration |

---

## Quick start (register → sign → verify)

```python
import os
from citizenofthecloud import register_agent, CloudIdentity, verify_agent

# 1. Register a new agent (one-time; needs an SDK token from /account)
reg = register_agent(
    sdk_token=os.environ["COTC_SDK_TOKEN"],
    name="My Research Bot",
    declared_purpose="Summarize papers and surface trends",
    autonomy_level="tool",
)
print(reg["cloud_id"])
print(reg["private_key"])    # STORE SECURELY

# 2. Sign an outbound request
import requests
me = CloudIdentity(cloud_id=reg["cloud_id"], private_key=reg["private_key"])
response = requests.post(
    "https://other-agent.com/api/task",
    json={"task": "analyze"},
    headers=me.sign(),
)

# 3. On the receiving side — verify an inbound request
result = verify_agent(request.headers)
if result["verified"]:
    print(f"Verified: {result['agent']['name']} (trust {result['agent']['trust_score']})")
```

---

## Examples per surface

### Key management (#13 generate-keypair)

```python
from citizenofthecloud import generate_key_pair

keys = generate_key_pair()
print(keys["public_key"])    # submit during manual registration
print(keys["private_key"])   # keep secret
```

### Registration (#17 register-agent)

```python
from citizenofthecloud import register_agent

result = register_agent(
    sdk_token=os.environ["COTC_SDK_TOKEN"],
    name="My Research Bot",
    declared_purpose="Summarize papers and surface trends",
    autonomy_level="tool",   # 'tool' | 'assistant' | 'agent' | 'self-directing'
    capabilities=["summarize", "cite"],
    operational_domain="research-lab.example.com",
)
```

### Outbound signing (#10 sign-headers, #11 sign-request, #12 cloud-fetch)

```python
from citizenofthecloud import CloudIdentity, cloud_fetch

me = CloudIdentity(
    cloud_id=os.environ["CLOUD_ID"],
    private_key=os.environ["CLOUD_PRIVATE_KEY"],
)

# 10 — simple (signs cloud_id + timestamp)
headers = me.sign()

# 11 — request-bound (also signs URL + method + body hash)
req_headers = me.sign_request(
    "https://other.example.com/api/data",
    method="POST",
    body='{"q":"x"}',
)

# 12 — convenience: HTTP call with auto-signed request-bound headers
resp = cloud_fetch(me, "https://other.example.com/api/data",
                   method="POST", body='{"q":"x"}')
print(resp["status"], resp["body"])
```

### Inbound verification (#5 verify-agent, #6 verify-request, #14 trust-policy)

```python
from citizenofthecloud import verify_agent, verify_request, TrustPolicy

policy = TrustPolicy(
    minimum_trust_score=0.5,
    require_covenant=True,
    allowed_autonomy_levels=["agent", "assistant"],
)

# 5 — simple header verification
r1 = verify_agent(request.headers, policy=policy)

# 6 — request-bound (catches URL / method / body tampering)
r2 = verify_request(
    request.headers,
    url=request.url, method=request.method, body=request.body,
    policy=policy,
)

if not r2["verified"]:
    return {"error": r2["reason"]}, 401
print(f"Verified {r2['agent']['name']}")
```

### Challenge / Respond (#7, #8, #9 prove-identity)

```python
from citizenofthecloud import (
    CloudIdentity, request_challenge, submit_challenge_response,
)

me = CloudIdentity(cloud_id="cc-...", private_key="-----BEGIN PRIVATE KEY-----\n...")

# 9 — full self-prove loop in one call (recommended)
verified = me.prove_identity()
print(verified["verified"])   # True

# Or — compose the three steps manually:
# 7 — request challenge
challenge = request_challenge("https://citizenofthecloud.com", me.cloud_id)
# (signing happens locally with the private key)
# 8 — submit response
result = submit_challenge_response(
    "https://citizenofthecloud.com", me.cloud_id, challenge["nonce"], signature_b64,
)
```

### Registry queries (#1, #2, #3, #4)

```python
from citizenofthecloud import (
    lookup_agent, list_directory, get_governance_feed, CloudIdentity,
)

# 1 — Look up another agent
agent = lookup_agent("https://citizenofthecloud.com", "cc-abc...")

# 2 — Fetch your own passport
me = CloudIdentity(cloud_id="cc-...", private_key="-----BEGIN ...")
my_passport = me.get_passport()

# 3 — Browse the public directory
agents = list_directory("https://citizenofthecloud.com")

# 4 — Read the governance event feed
feed = get_governance_feed("https://citizenofthecloud.com")
```

#### Reading the reputation block (Layer 3)

`lookup_agent()` now surfaces a `reputation` field alongside the composite `trust_score`.
The composite stays at `agent["trust_score"]`; the component signals live at `agent["reputation"]`
and let relying parties weight inputs against their own use case. Signals refresh every 5 minutes;
a freshly registered agent may return `reputation: None` — treat null as "not enough data yet,"
not as "zero across all signals."

```python
agent = lookup_agent("https://citizenofthecloud.com", "cc-abc...")

# Composite — fast threshold check
if agent["trust_score"] >= 0.5:
    ...

# Components — hard-reject on any upheld report, regardless of composite
rep = agent.get("reputation")
if rep and rep["reports_upheld"] >= 1:
    raise PermissionError("agent has upheld governance reports")

# Recency-weighted reliability — prefer 30-day success rate for long-lived agents
if rep and rep["lifetime_verifications"] >= 100 and rep["success_rate_30d"] >= 0.9:
    accept(agent)
```

### FastAPI route guard (#16 http-middleware)

```python
from fastapi import FastAPI, Depends
from citizenofthecloud import TrustPolicy
from citizenofthecloud.fastapi import cloud_guard, CloudGuard

app = FastAPI()

# Option A — per-route Depends() guard (returns the verified agent)
@app.post("/api/task")
async def task(agent=Depends(cloud_guard(TrustPolicy(minimum_trust_score=0.5)))):
    return {"hello": agent["name"]}

# Option B — app-wide ASGI middleware
app.add_middleware(CloudGuard, policy=TrustPolicy(minimum_trust_score=0.5))
```

### Cache control (#15 clear-cache)

```python
from citizenofthecloud import clear_cache
clear_cache()   # useful in tests, or after a trust-score update
```

---

## Environment variables

| Variable | Description |
|---|---|
| `CLOUD_ID` | Your agent's Cloud ID (e.g., `cc-7f3a9b2e-...`) |
| `CLOUD_PRIVATE_KEY` | Your agent's Ed25519 private key (PEM format) |
| `COTC_SDK_TOKEN` | Bootstrap SDK token (`cotc_sdk_*`) for `register_agent()` and `report-agent` flows. Get one at [citizenofthecloud.com/account](https://citizenofthecloud.com/account). |

---

## Links

- [citizenofthecloud.com](https://citizenofthecloud.com)
- [Documentation](https://citizenofthecloud.com/docs)
- [Specification](https://citizenofthecloud.com/spec)
- [Account / SDK tokens](https://citizenofthecloud.com/account)
- Sister SDKs: [sdk-js](https://github.com/citizenofthecloud/sdk-js) · [sdk-go](https://github.com/citizenofthecloud/sdk-go) · [sdk-rust](https://github.com/citizenofthecloud/sdk-rust)
- Framework integrations: [langchain](https://github.com/citizenofthecloud/langchain) · [crewai](https://github.com/citizenofthecloud/crewai) · [agent-framework](https://github.com/citizenofthecloud/agent-framework)
- [MCP server](https://github.com/citizenofthecloud/mcp-server)

## License

MIT
