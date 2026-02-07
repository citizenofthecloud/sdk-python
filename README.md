# citizenofthecloud

Identity and authentication for autonomous AI agents. Python SDK.

**Prove who you are. Verify who you're talking to.**

## Install

```bash
pip install cryptography
```

Then clone or copy the `citizenofthecloud/` package into your project.

## Quick Start

### Sign outbound requests

```python
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

### Generate keys

```python
from citizenofthecloud import generate_key_pair

keys = generate_key_pair()
print(keys["public_key"])   # submit during registration
print(keys["private_key"])  # keep secret
```

## Run the Proof of Concept

```bash
# Make sure the registry is running on localhost:3001
pip install cryptography
python poc.py
```

## License

MIT
