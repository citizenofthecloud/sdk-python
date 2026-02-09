#!/usr/bin/env python3
"""
══════════════════════════════════════════════════════════════
 Citizen of the Cloud — Python SDK Verification Test
══════════════════════════════════════════════════════════════

This script uses the actual citizenofthecloud Python SDK to test the
full verification flow:

  1. Generate key pairs for two agents
  2. Register both agents with the registry
  3. Agent A signs a request → verified against registry
  4. Agent B signs a request → verified against registry
  5. Tests failure cases (wrong key, missing headers, fake ID, expired)
  6. Tests Trust Policy enforcement

Prerequisites:
  pip install citizenofthecloud
  - The registry site must be running (npm run dev)
  - You need a valid auth token (see get-token.js)

Usage:
  python test-sdk-verification.py <your-auth-token>
"""

import sys
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

from citizenofthecloud import (
    CloudIdentity,
    generate_key_pair,
    verify_agent,
    clear_cache,
    TrustPolicy,
    CloudSDKError,
)

# ── Config ──
REGISTRY_URL = "http://localhost:3000"
AUTH_TOKEN = sys.argv[1] if len(sys.argv) > 1 else None

if not AUTH_TOKEN:
    print("\n❌ Usage: python test-sdk-verification.py <your-auth-token>")
    print("\nTo get your token:")
    print("  1. Sign in at http://localhost:3000")
    print("  2. Open browser console (F12)")
    print("  3. Paste: JSON.parse(localStorage.getItem(Object.keys(localStorage).find(k => k.includes('auth-token')))).access_token")
    print("  4. Copy the token\n")
    sys.exit(1)


# ── Colors ──
BOLD = "\033[1m"
GREEN = "\033[32m"
RED = "\033[31m"
DIM = "\033[2m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def header(text):
    print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
    print(f"  {BOLD}{text}{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 60}{RESET}\n")

def passed(text):
    print(f"  {GREEN}✓{RESET} {text}")

def failed(text):
    print(f"  {RED}✗{RESET} {text}")

def info(text):
    print(f"  {DIM}{text}{RESET}")


# ── Helper: Register agent via authenticated API ──

def register_agent(name, purpose, autonomy_level, public_key):
    """Register an agent using the authenticated API."""
    data = json.dumps({
        "name": name,
        "declared_purpose": purpose,
        "autonomy_level": autonomy_level,
        "capabilities": ["api_calls", "reasoning"],
        "operational_domain": "sdk-test",
        "creator": "Python SDK Test",
        "public_key": public_key,
        "covenant_signed": True,
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{REGISTRY_URL}/api/register",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {AUTH_TOKEN}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode("utf-8"))
        raise Exception(f"Registration failed ({e.code}): {body.get('error', 'Unknown')}")


def make_expired_headers(cloud_id, private_key_pem):
    """Create headers with a 6-minute-old timestamp."""
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
    print(f"\n{BOLD}╔══════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║  CITIZEN OF THE CLOUD — Python SDK Verification Test  ║{RESET}")
    print(f"{BOLD}║  Using the citizenofthecloud package                  ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════════════════╝{RESET}")
    print(f"\n  {DIM}Registry: {REGISTRY_URL}{RESET}")

    test_results = []

    # ──────────────────────────────────────────────
    # STEP 1: Generate key pairs using the SDK
    # ──────────────────────────────────────────────
    header("STEP 1: Generate Key Pairs (SDK)")

    keys_a = generate_key_pair()
    passed("Agent A key pair generated (Ed25519)")
    info(f"Public key: {keys_a['public_key'].splitlines()[1][:40]}...")

    keys_b = generate_key_pair()
    passed("Agent B key pair generated (Ed25519)")
    info(f"Public key: {keys_b['public_key'].splitlines()[1][:40]}...")

    # ──────────────────────────────────────────────
    # STEP 2: Register both agents
    # ──────────────────────────────────────────────
    header("STEP 2: Register Agents")

    try:
        agent_a = register_agent(
            "PySDK-SentinelBot",
            "Python SDK test agent — security monitoring and verification testing.",
            "agent",
            keys_a["public_key"],
        )
        passed(f"Agent A registered: {BOLD}{agent_a['passport']['name']}{RESET}")
        info(f"Cloud ID: {agent_a['cloud_id']}")
    except Exception as e:
        failed(f"Agent A registration failed: {e}")
        if "public key" in str(e).lower():
            info("Hint: Delete previous test agents from Supabase and try again.")
        return

    try:
        agent_b = register_agent(
            "PySDK-ResearchBot",
            "Python SDK test agent — autonomous research and data analysis.",
            "agent",
            keys_b["public_key"],
        )
        passed(f"Agent B registered: {BOLD}{agent_b['passport']['name']}{RESET}")
        info(f"Cloud ID: {agent_b['cloud_id']}")
    except Exception as e:
        failed(f"Agent B registration failed: {e}")
        return

    # ──────────────────────────────────────────────
    # STEP 3: Create CloudIdentity instances
    # ──────────────────────────────────────────────
    header("STEP 3: Initialize CloudIdentity (SDK)")

    identity_a = CloudIdentity(
        cloud_id=agent_a["cloud_id"],
        private_key=keys_a["private_key"],
        registry_url=REGISTRY_URL,
    )
    passed(f"Agent A identity created: {identity_a.cloud_id}")

    identity_b = CloudIdentity(
        cloud_id=agent_b["cloud_id"],
        private_key=keys_b["private_key"],
        registry_url=REGISTRY_URL,
    )
    passed(f"Agent B identity created: {identity_b.cloud_id}")

    # ──────────────────────────────────────────────
    # STEP 4: Agent A signs → verify against registry
    # ──────────────────────────────────────────────
    header("STEP 4: Agent A Signs Request → Verify via Registry")

    headers_a = identity_a.sign()
    info("Signed headers:")
    info(f"  X-Cloud-ID: {headers_a['X-Cloud-ID']}")
    info(f"  X-Cloud-Timestamp: {headers_a['X-Cloud-Timestamp']}")
    info(f"  X-Cloud-Signature: {headers_a['X-Cloud-Signature'][:40]}...")

    clear_cache()
    result_a = verify_agent(headers_a, registry_url=REGISTRY_URL)

    if result_a["verified"]:
        passed(f"{BOLD}VERIFIED{RESET} — Agent A's identity confirmed")
        info(f"  Name: {result_a['agent']['name']}")
        info(f"  Purpose: {result_a['agent']['declared_purpose']}")
        info(f"  Autonomy: {result_a['agent']['autonomy_level']}")
        info(f"  Status: {result_a['agent']['status']}")
        info(f"  Covenant: {'signed' if result_a['agent'].get('covenant_signed') else 'unsigned'}")
        info(f"  Latency: {result_a.get('latency', '?')}ms")
        test_results.append(True)
    else:
        failed(f"Verification failed: {result_a.get('reason')}")
        test_results.append(False)

    # ──────────────────────────────────────────────
    # STEP 5: Agent B signs → verify against registry
    # ──────────────────────────────────────────────
    header("STEP 5: Agent B Signs Request → Verify via Registry")

    headers_b = identity_b.sign()
    info("Signed headers:")
    info(f"  X-Cloud-ID: {headers_b['X-Cloud-ID']}")
    info(f"  X-Cloud-Timestamp: {headers_b['X-Cloud-Timestamp']}")
    info(f"  X-Cloud-Signature: {headers_b['X-Cloud-Signature'][:40]}...")

    clear_cache()
    result_b = verify_agent(headers_b, registry_url=REGISTRY_URL)

    if result_b["verified"]:
        passed(f"{BOLD}VERIFIED{RESET} — Agent B's identity confirmed")
        info(f"  Name: {result_b['agent']['name']}")
        info(f"  Latency: {result_b.get('latency', '?')}ms")
        test_results.append(True)
    else:
        failed(f"Verification failed: {result_b.get('reason')}")
        test_results.append(False)

    # ──────────────────────────────────────────────
    # STEP 6: Fetch passport using SDK
    # ──────────────────────────────────────────────
    header("STEP 6: Fetch Passport via SDK")

    passport = identity_a.get_passport()
    if passport and passport.get("cloud_id") == agent_a["cloud_id"]:
        passed(f"Passport retrieved for {passport['name']}")
        info(f"  Cloud ID: {passport['cloud_id']}")
        info(f"  Status: {passport['status']}")
        info(f"  Registered: {passport.get('registration_date', 'unknown')}")
        test_results.append(True)
    else:
        failed("Failed to retrieve passport")
        test_results.append(False)

    # ──────────────────────────────────────────────
    # STEP 7: Failure cases
    # ──────────────────────────────────────────────
    header("STEP 7: Failure Cases")

    # 7a: Wrong key
    info("Test 7a: Wrong private key (impersonation attempt)")
    wrong_identity = CloudIdentity(
        cloud_id=agent_a["cloud_id"],
        private_key=keys_b["private_key"],
        registry_url=REGISTRY_URL,
    )
    wrong_headers = wrong_identity.sign()
    clear_cache()
    wrong_result = verify_agent(wrong_headers, registry_url=REGISTRY_URL)
    if not wrong_result["verified"] and wrong_result["reason"] == "invalid_signature":
        passed(f"Blocked: {wrong_result['reason']}")
        test_results.append(True)
    else:
        failed(f"Should have been rejected: {wrong_result}")
        test_results.append(False)

    # 7b: Missing headers
    info("\nTest 7b: Missing authentication headers")
    clear_cache()
    missing_result = verify_agent({}, registry_url=REGISTRY_URL)
    if not missing_result["verified"] and missing_result["reason"] == "missing_headers":
        passed(f"Blocked: {missing_result['reason']}")
        test_results.append(True)
    else:
        failed(f"Should have been rejected: {missing_result}")
        test_results.append(False)

    # 7c: Fake Cloud ID
    info("\nTest 7c: Unregistered Cloud ID")
    fake_identity = CloudIdentity(
        cloud_id="cc-00000000-fake-0000-0000-000000000000",
        private_key=keys_a["private_key"],
        registry_url=REGISTRY_URL,
    )
    fake_headers = fake_identity.sign()
    clear_cache()
    fake_result = verify_agent(fake_headers, registry_url=REGISTRY_URL)
    if not fake_result["verified"] and fake_result["reason"] == "invalid_cloud_id":
        passed(f"Blocked: {fake_result['reason']}")
        test_results.append(True)
    else:
        failed(f"Should have been rejected: {fake_result}")
        test_results.append(False)

    # 7d: Expired timestamp
    info("\nTest 7d: Expired timestamp (6 minutes old)")
    expired_headers = make_expired_headers(agent_a["cloud_id"], keys_a["private_key"])
    clear_cache()
    expired_result = verify_agent(expired_headers, registry_url=REGISTRY_URL)
    if not expired_result["verified"] and expired_result["reason"] == "timestamp_expired":
        passed(f"Blocked: {expired_result['reason']}")
        test_results.append(True)
    else:
        failed(f"Should have been rejected: {expired_result}")
        test_results.append(False)

    # 7e: Partial headers
    info("\nTest 7e: Partial headers (missing signature)")
    partial_headers = {
        "X-Cloud-ID": agent_a["cloud_id"],
        "X-Cloud-Timestamp": datetime.now(timezone.utc).isoformat(),
    }
    clear_cache()
    partial_result = verify_agent(partial_headers, registry_url=REGISTRY_URL)
    if not partial_result["verified"] and partial_result["reason"] == "missing_headers":
        passed(f"Blocked: {partial_result['reason']}")
        test_results.append(True)
    else:
        failed(f"Should have been rejected: {partial_result}")
        test_results.append(False)

    # ──────────────────────────────────────────────
    # STEP 8: Trust Policy enforcement
    # ──────────────────────────────────────────────
    header("STEP 8: Trust Policy Enforcement")

    # 8a: Block specific agent
    info("Test 8a: Blocked agent list")
    blocked_policy = TrustPolicy(
        blocked_agents=[agent_b["cloud_id"]],
        registry_url=REGISTRY_URL,
    )
    headers_b_fresh = identity_b.sign()
    clear_cache()
    blocked_result = verify_agent(headers_b_fresh, policy=blocked_policy)
    if not blocked_result["verified"] and blocked_result["reason"] == "agent_blocked":
        passed(f"Blocked: {blocked_result['reason']}")
        test_results.append(True)
    else:
        failed(f"Should have been blocked: {blocked_result}")
        test_results.append(False)

    # 8b: Restrict autonomy levels
    info("\nTest 8b: Autonomy level restriction (only 'tool' allowed)")
    autonomy_policy = TrustPolicy(
        allowed_autonomy_levels=["tool"],
        registry_url=REGISTRY_URL,
    )
    headers_a_fresh = identity_a.sign()
    clear_cache()
    autonomy_result = verify_agent(headers_a_fresh, policy=autonomy_policy)
    if not autonomy_result["verified"] and autonomy_result["reason"] == "autonomy_level_restricted":
        passed(f"Blocked: {autonomy_result['reason']} (agent is 'agent', policy requires 'tool')")
        test_results.append(True)
    else:
        failed(f"Should have been restricted: {autonomy_result}")
        test_results.append(False)

    # 8c: Allow correct autonomy level
    info("\nTest 8c: Autonomy level match (allow 'agent')")
    allow_policy = TrustPolicy(
        allowed_autonomy_levels=["agent", "assistant"],
        registry_url=REGISTRY_URL,
    )
    headers_a_fresh2 = identity_a.sign()
    clear_cache()
    allow_result = verify_agent(headers_a_fresh2, policy=allow_policy)
    if allow_result["verified"]:
        passed(f"Allowed: agent autonomy level is permitted")
        test_results.append(True)
    else:
        failed(f"Should have been allowed: {allow_result}")
        test_results.append(False)

    # 8d: Custom max age (very short)
    info("\nTest 8d: Custom max age (1 second — should expire quickly)")
    time.sleep(2)  # Wait 2 seconds
    short_policy = TrustPolicy(
        max_age=1,
        registry_url=REGISTRY_URL,
    )
    clear_cache()
    short_result = verify_agent(headers_b, policy=short_policy)
    if not short_result["verified"] and short_result["reason"] == "timestamp_expired":
        passed(f"Blocked: {short_result['reason']} (signed >1 second ago)")
        test_results.append(True)
    else:
        failed(f"Should have expired: {short_result}")
        test_results.append(False)

    # ──────────────────────────────────────────────
    # SUMMARY
    # ──────────────────────────────────────────────
    header("SUMMARY")

    total = len(test_results)
    pass_count = sum(test_results)
    fail_count = total - pass_count

    if all(test_results):
        print(f"  {GREEN}{BOLD}All {total} tests passed.{RESET}")
        print(f"  {DIM}")
        print(f"  Two agents registered and verified using the Python SDK.")
        print(f"  Signed headers verified cryptographically against the registry.")
        print(f"  Five attack vectors correctly rejected.")
        print(f"  Trust policies enforced (blocklist, autonomy, max age).")
        print(f"  {RESET}")
    else:
        print(f"  {RED}{BOLD}{fail_count}/{total} tests failed.{RESET}")

    print(f"  {DIM}Registry: {REGISTRY_URL}")
    print(f"  Agent A: {agent_a['cloud_id']}")
    print(f"  Agent B: {agent_b['cloud_id']}{RESET}")

    print(f"\n  {DIM}To clean up test agents:{RESET}")
    print(f"  {DIM}DELETE FROM agents WHERE name IN ('PySDK-SentinelBot', 'PySDK-ResearchBot');{RESET}\n")


if __name__ == "__main__":
    main()
