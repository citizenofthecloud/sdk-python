#!/usr/bin/env python3
"""
══════════════════════════════════════════════════════════════
 Citizen of the Cloud — Python Proof of Concept
 Two agents authenticating with each other
══════════════════════════════════════════════════════════════

This demo:
  1. Generates key pairs for two agents
  2. Registers both agents with the live registry
  3. Agent A signs a request → Agent B verifies it
  4. Agent B signs a request → Agent A verifies it
  5. Tests failure cases (bad signature, wrong key, expired timestamp)

Run:
  pip install cryptography
  python poc.py
"""

import json
import hashlib
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

from citizenofthecloud import (
    CloudIdentity,
    generate_key_pair,
    verify_agent,
    clear_cache,
)

REGISTRY_URL = "http://localhost:3001"

# ── Colors ──
BOLD = "\033[1m"
GREEN = "\033[32m"
RED = "\033[31m"
DIM = "\033[2m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def header(text):
    print(f"\n{BOLD}{CYAN}═══ {text} ═══{RESET}\n")

def passed(text):
    print(f"  {GREEN}✓{RESET} {text}")

def failed(text):
    print(f"  {RED}✗{RESET} {text}")

def info(text):
    print(f"  {DIM}{text}{RESET}")


# ── Helpers ──

def register_agent(name, purpose, autonomy_level, public_key):
    data = json.dumps({
        "name": name,
        "declared_purpose": purpose,
        "autonomy_level": autonomy_level,
        "capabilities": ["api_calls", "reasoning"],
        "operational_domain": "proof of concept",
        "creator": "citizenofthecloud.com",
        "public_key": public_key,
        "covenant_signed": True,
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{REGISTRY_URL}/api/register",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode("utf-8"))
        raise Exception(f"Registration failed: {body.get('error', e.code)}")


def make_expired_headers(cloud_id, private_key_pem):
    """Create headers with a 6-minute-old timestamp for testing."""
    from cryptography.hazmat.primitives import serialization as ser
    import base64

    private_key = ser.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )
    expired_time = (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat()
    payload = f"{cloud_id}:{expired_time}".encode("utf-8")
    signature = private_key.sign(payload)
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")

    return {
        "X-Cloud-ID": cloud_id,
        "X-Cloud-Timestamp": expired_time,
        "X-Cloud-Signature": sig_b64,
    }


# ── Main ──

def main():
    print(f"\n{BOLD}╔══════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║  CITIZEN OF THE CLOUD — Python Proof of Concept  ║{RESET}")
    print(f"{BOLD}║  Agent-to-Agent Authentication Demo               ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════════════╝{RESET}")

    # ── Step 1: Generate keys ──
    header("STEP 1: Generate Key Pairs")

    keys_a = generate_key_pair()
    passed("Agent A key pair generated (Ed25519)")
    info(f"Public key: {keys_a['public_key'].splitlines()[1][:40]}...")

    keys_b = generate_key_pair()
    passed("Agent B key pair generated (Ed25519)")
    info(f"Public key: {keys_b['public_key'].splitlines()[1][:40]}...")

    # ── Step 2: Register agents ──
    header("STEP 2: Register Agents")

    try:
        agent_a = register_agent(
            "PyResearchBot-POC",
            "Python proof of concept agent that requests analysis from other agents",
            "agent",
            keys_a["public_key"],
        )
        passed(f"Agent A registered: {BOLD}{agent_a['passport']['name']}{RESET}")
        info(f"Cloud ID: {agent_a['cloud_id']}")
    except Exception as e:
        failed(f"Agent A registration failed: {e}")
        return

    try:
        agent_b = register_agent(
            "PyAnalysisBot-POC",
            "Python proof of concept agent that performs data analysis",
            "agent",
            keys_b["public_key"],
        )
        passed(f"Agent B registered: {BOLD}{agent_b['passport']['name']}{RESET}")
        info(f"Cloud ID: {agent_b['cloud_id']}")
    except Exception as e:
        failed(f"Agent B registration failed: {e}")
        return

    # ── Step 3: Agent A → Agent B ──
    header("STEP 3: Agent A signs request → Agent B verifies")

    identity_a = CloudIdentity(
        cloud_id=agent_a["cloud_id"],
        private_key=keys_a["private_key"],
        registry_url=REGISTRY_URL,
    )

    headers_a = identity_a.sign()
    info("Signed headers:")
    info(f"  X-Cloud-ID: {headers_a['X-Cloud-ID']}")
    info(f"  X-Cloud-Timestamp: {headers_a['X-Cloud-Timestamp']}")
    info(f"  X-Cloud-Signature: {headers_a['X-Cloud-Signature'][:40]}...")

    clear_cache()
    result_a_to_b = verify_agent(headers_a, registry_url=REGISTRY_URL)

    if result_a_to_b["verified"]:
        passed(f"{BOLD}VERIFIED{RESET} — Agent B confirmed Agent A's identity")
        info(f"  Name: {result_a_to_b['agent']['name']}")
        info(f"  Purpose: {result_a_to_b['agent']['declared_purpose']}")
        info(f"  Autonomy: {result_a_to_b['agent']['autonomy_level']}")
        info(f"  Latency: {result_a_to_b['latency']}ms")
    else:
        failed(f"Verification failed: {result_a_to_b.get('reason')}")

    # ── Step 4: Agent B → Agent A ──
    header("STEP 4: Agent B signs request → Agent A verifies")

    identity_b = CloudIdentity(
        cloud_id=agent_b["cloud_id"],
        private_key=keys_b["private_key"],
        registry_url=REGISTRY_URL,
    )

    headers_b = identity_b.sign()
    info("Signed headers:")
    info(f"  X-Cloud-ID: {headers_b['X-Cloud-ID']}")
    info(f"  X-Cloud-Timestamp: {headers_b['X-Cloud-Timestamp']}")
    info(f"  X-Cloud-Signature: {headers_b['X-Cloud-Signature'][:40]}...")

    clear_cache()
    result_b_to_a = verify_agent(headers_b, registry_url=REGISTRY_URL)

    if result_b_to_a["verified"]:
        passed(f"{BOLD}VERIFIED{RESET} — Agent A confirmed Agent B's identity")
        info(f"  Name: {result_b_to_a['agent']['name']}")
        info(f"  Latency: {result_b_to_a['latency']}ms")
    else:
        failed(f"Verification failed: {result_b_to_a.get('reason')}")

    # ── Step 5: Failure cases ──
    header("STEP 5: Failure Cases")

    # 5a. Wrong private key
    info("Test: Agent A signs with WRONG key...")
    wrong_identity = CloudIdentity(
        cloud_id=agent_a["cloud_id"],
        private_key=keys_b["private_key"],  # B's key for A's ID
        registry_url=REGISTRY_URL,
    )
    wrong_headers = wrong_identity.sign()
    clear_cache()
    wrong_result = verify_agent(wrong_headers, registry_url=REGISTRY_URL)
    if not wrong_result["verified"] and wrong_result["reason"] == "invalid_signature":
        passed(f"Correctly rejected: {wrong_result['reason']}")
    else:
        failed(f"Should have been rejected: {wrong_result}")

    # 5b. Missing headers
    info("Test: Missing authentication headers...")
    clear_cache()
    missing_result = verify_agent({}, registry_url=REGISTRY_URL)
    if not missing_result["verified"] and missing_result["reason"] == "missing_headers":
        passed(f"Correctly rejected: {missing_result['reason']}")
    else:
        failed(f"Should have been rejected: {missing_result}")

    # 5c. Fake Cloud ID
    info("Test: Unregistered Cloud ID...")
    fake_identity = CloudIdentity(
        cloud_id="cc-00000000-fake-0000-0000-000000000000",
        private_key=keys_a["private_key"],
        registry_url=REGISTRY_URL,
    )
    fake_headers = fake_identity.sign()
    clear_cache()
    fake_result = verify_agent(fake_headers, registry_url=REGISTRY_URL)
    if not fake_result["verified"] and fake_result["reason"] == "invalid_cloud_id":
        passed(f"Correctly rejected: {fake_result['reason']}")
    else:
        failed(f"Should have been rejected: {fake_result}")

    # 5d. Expired timestamp
    info("Test: Expired timestamp (6 minutes old)...")
    expired_headers = make_expired_headers(agent_a["cloud_id"], keys_a["private_key"])
    clear_cache()
    expired_result = verify_agent(expired_headers, registry_url=REGISTRY_URL)
    if not expired_result["verified"] and expired_result["reason"] == "timestamp_expired":
        passed(f"Correctly rejected: {expired_result['reason']}")
    else:
        failed(f"Should have been rejected: {expired_result}")

    # ── Summary ──
    header("SUMMARY")

    all_passed = (
        result_a_to_b["verified"]
        and result_b_to_a["verified"]
        and not wrong_result["verified"]
        and not missing_result["verified"]
        and not fake_result["verified"]
        and not expired_result["verified"]
    )

    if all_passed:
        print(f"  {GREEN}{BOLD}All tests passed.{RESET}")
        print(f"  {DIM}Two autonomous agents successfully authenticated")
        print(f"  with each other using the Cloud Identity protocol.")
        print(f"  Four attack vectors correctly rejected.{RESET}")
    else:
        print(f"  {RED}{BOLD}Some tests failed.{RESET}")

    print(f"\n  {DIM}Registry: {REGISTRY_URL}")
    print(f"  Agent A: {agent_a['cloud_id']}")
    print(f"  Agent B: {agent_b['cloud_id']}{RESET}\n")


if __name__ == "__main__":
    main()
