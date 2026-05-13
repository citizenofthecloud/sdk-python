"""
citizenofthecloud — Identity and authentication for autonomous AI agents.

Prove who you are. Verify who you're talking to.
"""

import hashlib
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    raise ImportError(
        "The 'cryptography' package is required. Install it with: "
        "pip install cryptography"
    )

__version__ = "0.1.0"
__all__ = [
    "CloudIdentity",
    "verify_agent",
    "verify_request",
    "generate_key_pair",
    "cloud_fetch",
    "TrustPolicy",
    "CloudSDKError",
    "RegistryError",
    "clear_cache",
    "request_challenge",
    "submit_challenge_response",
    "lookup_agent",
    "list_directory",
    "get_governance_feed",
    "register_agent",
]

DEFAULT_REGISTRY = "https://citizenofthecloud.com"
DEFAULT_MAX_AGE = 300  # 5 minutes


# ─── Errors ───────────────────────────────────────────────────

class CloudSDKError(Exception):
    """SDK misconfiguration error."""
    pass


class RegistryError(Exception):
    """Error communicating with the registry."""
    pass


# ─── Key Generation ───────────────────────────────────────────

def generate_key_pair() -> dict:
    """
    Generate an Ed25519 key pair for agent identity.

    Returns:
        dict with 'public_key' and 'private_key' as PEM-encoded strings.

    Example:
        keys = generate_key_pair()
        print(keys['public_key'])   # submit during registration
        print(keys['private_key'])  # keep secret
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return {"public_key": public_pem, "private_key": private_pem}


# ─── Cloud Identity ──────────────────────────────────────────

class CloudIdentity:
    """
    Represents an agent's identity. Used to sign outbound requests.

    Example:
        identity = CloudIdentity(
            cloud_id="cc-7f3a9b2e-...",
            private_key=os.environ["CLOUD_PRIVATE_KEY"],
        )
        headers = identity.sign()
    """

    def __init__(
        self,
        cloud_id: str,
        private_key: str,
        registry_url: str = DEFAULT_REGISTRY,
    ):
        if not cloud_id:
            raise CloudSDKError("cloud_id is required")
        if not private_key:
            raise CloudSDKError("private_key is required")

        self.cloud_id = cloud_id
        self.registry_url = registry_url.rstrip("/")

        try:
            self._private_key = serialization.load_pem_private_key(
                private_key.encode("utf-8"),
                password=None,
            )
        except Exception as e:
            raise CloudSDKError(f"Invalid private key: {e}")

    def sign(self) -> dict:
        """
        Generate authentication headers for an outbound request.
        Signature covers: {cloud_id}:{timestamp}

        Returns:
            dict of headers to include in the request.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = f"{self.cloud_id}:{timestamp}"
        signature = self._private_key.sign(payload.encode("utf-8"))

        return {
            "X-Cloud-ID": self.cloud_id,
            "X-Cloud-Timestamp": timestamp,
            "X-Cloud-Signature": _base64url_encode(signature),
        }

    def sign_request(self, url: str, method: str, body: str = "") -> dict:
        """
        Generate request-bound authentication headers.
        Signature covers: {cloud_id}:{timestamp}:{method}:{url}:{body_hash}

        Args:
            url: The request URL
            method: HTTP method (GET, POST, etc.)
            body: Request body (optional)

        Returns:
            dict of headers to include in the request.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        body_hash = _base64url_encode(
            hashlib.sha256((body or "").encode("utf-8")).digest()
        )
        payload = f"{self.cloud_id}:{timestamp}:{method.upper()}:{url}:{body_hash}"
        signature = self._private_key.sign(payload.encode("utf-8"))

        return {
            "X-Cloud-ID": self.cloud_id,
            "X-Cloud-Timestamp": timestamp,
            "X-Cloud-Signature": _base64url_encode(signature),
            "X-Cloud-Request-Bound": "true",
        }

    def get_passport(self) -> dict:
        """
        Fetch this agent's passport from the registry.

        Returns:
            dict with the agent's passport data.
        """
        url = f"{self.registry_url}/api/verify?cloud_id={self.cloud_id}"
        data = _fetch_json(url)
        return data.get("agent")

    def prove_identity(self) -> dict:
        """
        Prove this agent's identity to the registry via the full challenge/respond
        cryptographic loop. The server issues a nonce, this method signs it with
        the private key, the server validates against the registered public key.

        This is the canonical identity-proof flow; the resulting verification_log
        row is server-witnessed (authenticated=true) and contributes to trust score.

        Returns:
            dict with keys: verified (bool), agent (dict, on success),
            error (str, on failure), timestamp (str).
        """
        import base64
        challenge = request_challenge(self.registry_url, self.cloud_id)
        nonce = challenge["nonce"]
        # Server signs over the UTF-8 bytes of the hex nonce string (not the
        # decoded hex bytes) — see registry's lib/verification.js.
        signature_bytes = self._private_key.sign(nonce.encode("utf-8"))
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")
        return submit_challenge_response(
            self.registry_url, self.cloud_id, nonce, signature_b64
        )


# ─── Challenge / Respond ──────────────────────────────────────

def request_challenge(registry_url: str, cloud_id: str) -> dict:
    """
    Request a verification challenge for a cloud_id. The returned nonce must
    be signed with the agent's private key (over the UTF-8 bytes of the hex
    string) and submitted via submit_challenge_response().

    Args:
        registry_url: Registry base URL
        cloud_id: The agent's Cloud ID

    Returns:
        dict with keys: nonce (str, hex), expires_in (int, seconds).
    """
    url = f"{registry_url.rstrip('/')}/api/verify/challenge"
    body = json.dumps({"cloud_id": cloud_id}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        try:
            err_data = json.loads(err_body)
            raise RegistryError(err_data.get("error", f"Challenge request failed: {e.code}"))
        except (json.JSONDecodeError, ValueError):
            raise RegistryError(f"Challenge request failed: {e.code}")
    except urllib.error.URLError as e:
        raise RegistryError(f"Cannot reach registry: {e}")


def submit_challenge_response(
    registry_url: str, cloud_id: str, nonce: str, signature: str
) -> dict:
    """
    Submit a signed challenge response. The registry validates the signature
    against the agent's registered public key and returns the verified agent.

    Args:
        registry_url: Registry base URL
        cloud_id: The agent's Cloud ID
        nonce: The hex nonce returned by request_challenge()
        signature: Base64-encoded Ed25519 signature over the UTF-8 nonce bytes

    Returns:
        dict with keys: verified (bool), agent (dict, on success),
        error (str, on failure), timestamp (str).
    """
    url = f"{registry_url.rstrip('/')}/api/verify/respond"
    body = json.dumps({
        "cloud_id": cloud_id, "nonce": nonce, "signature": signature,
    }).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # respond returns non-2xx for failed verification — still parse the body
        try:
            return json.loads(e.read().decode("utf-8"))
        except (json.JSONDecodeError, ValueError):
            raise RegistryError(f"Respond request failed: {e.code}")
    except urllib.error.URLError as e:
        raise RegistryError(f"Cannot reach registry: {e}")


# ─── Registry queries (no auth) ───────────────────────────────


def lookup_agent(registry_url: str, cloud_id: str) -> Optional[dict]:
    """
    Look up an agent's public record by cloud_id.

    Args:
        registry_url: Registry base URL
        cloud_id: The agent's Cloud ID

    Returns:
        Agent dict with name, declared_purpose, autonomy_level, capabilities,
        operational_domain, covenant_signed, status, trust_score, public_key,
        registration_date, last_verified, owner_username — or None if not found.
    """
    url = f"{registry_url.rstrip('/')}/api/verify?cloud_id={cloud_id}"
    data = _fetch_json(url)
    if not data.get("verified"):
        return None
    return data.get("agent")


def list_directory(registry_url: str) -> list:
    """
    List public agent directory entries.

    Args:
        registry_url: Registry base URL

    Returns:
        List of agent dicts. Each entry contains the public-facing fields the
        registry exposes via /api/directory.
    """
    url = f"{registry_url.rstrip('/')}/api/directory"
    data = _fetch_json(url)
    return data.get("agents", data if isinstance(data, list) else [])


def get_governance_feed(registry_url: str) -> list:
    """
    Get the governance activity feed.

    Args:
        registry_url: Registry base URL

    Returns:
        List of governance event dicts.
    """
    url = f"{registry_url.rstrip('/')}/api/governance/feed"
    data = _fetch_json(url)
    return data.get("feed", data if isinstance(data, list) else [])


# ─── Registration (SDK token auth) ────────────────────────────


def register_agent(
    sdk_token: str,
    name: str,
    declared_purpose: str,
    autonomy_level: str = "tool",
    capabilities: Optional[list] = None,
    operational_domain: Optional[str] = None,
    covenant_signed: bool = True,
    registry_url: str = DEFAULT_REGISTRY,
) -> dict:
    """
    Register a new agent in a single call.

    Generates a fresh Ed25519 keypair locally, posts the public key plus the
    agent metadata to the registry, and returns the cloud_id together with
    both keys. The private key is returned to you and is never sent to the
    registry — store it securely.

    Args:
        sdk_token: A cotc_sdk_* token from your account at
            citizenofthecloud.com/account.
        name: Human-readable name for the agent.
        declared_purpose: What the agent does (<= 500 chars).
        autonomy_level: One of 'tool', 'assistant', 'agent', 'self-directing'.
        capabilities: Optional list of capability strings.
        operational_domain: Optional domain string.
        covenant_signed: Must be True to register (Non-Malicious Covenant).
        registry_url: Registry base URL.

    Returns:
        dict with keys: cloud_id, public_key, private_key, name,
        declared_purpose, autonomy_level, passport.

    Raises:
        RegistryError on HTTP failure.
        CloudSDKError if sdk_token is missing or malformed.
    """
    if not sdk_token or not sdk_token.startswith("cotc_sdk_"):
        raise CloudSDKError(
            "sdk_token must be a cotc_sdk_* token. Create one at "
            "citizenofthecloud.com/account."
        )

    keys = generate_key_pair()
    body = json.dumps({
        "name": name,
        "declared_purpose": declared_purpose,
        "autonomy_level": autonomy_level,
        "public_key": keys["public_key"],
        "covenant_signed": covenant_signed,
        "capabilities": capabilities or [],
        "operational_domain": operational_domain,
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{registry_url.rstrip('/')}/api/register",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {sdk_token}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            err = json.loads(e.read().decode("utf-8"))
            msg = err.get("error") or err.get("error_code") or str(e)
        except Exception:
            msg = f"HTTP {e.code}"
        raise RegistryError(f"Registration failed: {msg}") from e
    except urllib.error.URLError as e:
        raise RegistryError(f"Registry unreachable: {e}") from e

    return {
        "cloud_id": data["cloud_id"],
        "public_key": keys["public_key"],
        "private_key": keys["private_key"],
        "name": name,
        "declared_purpose": declared_purpose,
        "autonomy_level": autonomy_level,
        "passport": data.get("passport"),
    }


# ─── Verification ─────────────────────────────────────────────

# Simple in-memory cache
_cache: dict = {}
_CACHE_TTL = 300  # 5 minutes


def clear_cache():
    """Clear the verification cache."""
    _cache.clear()


def _get_cached(cloud_id: str) -> Optional[dict]:
    entry = _cache.get(cloud_id)
    if entry is None:
        return None
    if time.time() - entry["time"] > _CACHE_TTL:
        del _cache[cloud_id]
        return None
    return entry["data"]


def _set_cache(cloud_id: str, data: dict):
    _cache[cloud_id] = {"data": data, "time": time.time()}


class TrustPolicy:
    """
    Reusable trust rules for verification.

    Example:
        policy = TrustPolicy(
            minimum_trust_score=0.6,
            require_covenant=True,
            allowed_autonomy_levels=["agent", "assistant"],
        )
        result = verify_agent(headers, policy=policy)
    """

    def __init__(
        self,
        max_age: int = DEFAULT_MAX_AGE,
        require_covenant: bool = True,
        minimum_trust_score: Optional[float] = None,
        allowed_autonomy_levels: Optional[list] = None,
        blocked_agents: Optional[list] = None,
        registry_url: str = DEFAULT_REGISTRY,
        cache: bool = True,
    ):
        self.max_age = max_age
        self.require_covenant = require_covenant
        self.minimum_trust_score = minimum_trust_score
        self.allowed_autonomy_levels = allowed_autonomy_levels
        self.blocked_agents = blocked_agents
        self.registry_url = registry_url
        self.cache = cache


def _log_verification(registry_url, cloud_id, result_str, reason=None, latency=None):
    """Fire-and-forget verification log to the registry."""
    try:
        log_data = json.dumps({
            "cloud_id": cloud_id,
            "result": result_str,
            "reason": reason,
            "method": "sdk_headers",
            "latency": latency,
        }).encode("utf-8")

        log_url = f"{registry_url.rstrip('/')}/api/verify/log"
        log_req = urllib.request.Request(
            log_url,
            data=log_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(log_req, timeout=5)
    except Exception:
        # Best-effort — don't let logging failures affect verification
        pass


def verify_agent(
    headers: dict,
    policy: Optional[TrustPolicy] = None,
    **kwargs,
) -> dict:
    """
    Verify incoming request headers from another agent.

    Args:
        headers: Request headers dict (must include X-Cloud-ID,
                 X-Cloud-Timestamp, X-Cloud-Signature)
        policy: Optional TrustPolicy with verification rules.
        **kwargs: Override individual policy fields.

    Returns:
        dict with 'verified' (bool), 'reason' (str if rejected),
        'agent' (dict if found), 'timestamp', 'latency'.

    Example:
        result = verify_agent(request.headers)
        if result["verified"]:
            print(f"Verified: {result['agent']['name']}")
        else:
            print(f"Rejected: {result['reason']}")
    """
    result = _verify_agent_inner(headers, policy, **kwargs)

    # Log the verification result (best-effort, non-blocking)
    if policy is None:
        policy = TrustPolicy(**kwargs)
    cloud_id = headers.get("X-Cloud-ID") or headers.get("x-cloud-id") or "unknown"
    log_result = "success" if result["verified"] else result.get("reason", "unknown")
    _log_verification(
        policy.registry_url,
        cloud_id,
        log_result,
        reason=result.get("reason"),
        latency=result.get("latency"),
    )

    return result


def _verify_agent_inner(
    headers: dict,
    policy: Optional[TrustPolicy] = None,
    **kwargs,
) -> dict:
    """Internal verification logic — called by verify_agent which adds logging."""
    start = time.time()

    # Build options from policy + overrides
    if policy is None:
        policy = TrustPolicy(**kwargs)

    # Normalize headers (support both cases)
    def get(name):
        return headers.get(name) or headers.get(name.lower())

    cloud_id = get("X-Cloud-ID")
    timestamp = get("X-Cloud-Timestamp")
    signature = get("X-Cloud-Signature")

    # 1. Check headers present
    if not cloud_id or not timestamp or not signature:
        return _result(False, "missing_headers", start=start)

    # 2. Check blocked list
    if policy.blocked_agents and cloud_id in policy.blocked_agents:
        return _result(False, "agent_blocked", start=start)

    # 3. Validate timestamp
    try:
        signed_at = datetime.fromisoformat(timestamp)
        if signed_at.tzinfo is None:
            signed_at = signed_at.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - signed_at).total_seconds()
    except (ValueError, TypeError):
        return _result(False, "invalid_timestamp", start=start)

    if age > policy.max_age:
        return _result(False, "timestamp_expired", start=start)
    if age < -30:
        return _result(False, "timestamp_future", start=start)

    # 4. Lookup agent in registry (with cache)
    agent_data = None
    try:
        if policy.cache:
            agent_data = _get_cached(cloud_id)

        if agent_data is None:
            registry_url = policy.registry_url.rstrip("/")
            url = f"{registry_url}/api/verify?cloud_id={cloud_id}"
            data = _fetch_json(url)

            if not data.get("verified") or not data.get("agent"):
                return _result(False, "invalid_cloud_id", start=start)

            agent_data = data["agent"]

            if policy.cache:
                _set_cache(cloud_id, agent_data)

    except RegistryError:
        return _result(False, "registry_unreachable", start=start)
    except Exception:
        return _result(False, "registry_unreachable", start=start)

    # 5. Check agent status
    if agent_data.get("status") != "active":
        return _result(False, "agent_suspended", agent=agent_data, start=start)

    # 6. Check covenant
    if policy.require_covenant and not agent_data.get("covenant_signed"):
        return _result(False, "covenant_unsigned", agent=agent_data, start=start)

    # 7. Check trust score
    if policy.minimum_trust_score is not None:
        score = agent_data.get("trust_score")
        if score is None or score < policy.minimum_trust_score:
            return _result(
                False, "trust_score_insufficient", agent=agent_data, start=start
            )

    # 8. Check autonomy level
    if policy.allowed_autonomy_levels is not None:
        if agent_data.get("autonomy_level") not in policy.allowed_autonomy_levels:
            return _result(
                False, "autonomy_level_restricted", agent=agent_data, start=start
            )

    # 9. Verify cryptographic signature
    try:
        public_key = serialization.load_pem_public_key(
            agent_data["public_key"].encode("utf-8")
        )
        payload = f"{cloud_id}:{timestamp}".encode("utf-8")
        sig_bytes = _base64url_decode(signature)
        public_key.verify(sig_bytes, payload)
    except InvalidSignature:
        _cache.pop(cloud_id, None)
        return _result(False, "invalid_signature", agent=agent_data, start=start)
    except Exception:
        return _result(False, "invalid_signature", agent=agent_data, start=start)

    # 10. All checks passed
    return _result(True, agent=agent_data, timestamp=timestamp, start=start)


def verify_request(
    headers: dict,
    url: str,
    method: str,
    body: str = "",
    policy: Optional[TrustPolicy] = None,
    **kwargs,
) -> dict:
    """
    Verify with request-bound signature validation.

    Same as verify_agent but also checks URL, method, and body hash.
    """
    start = time.time()

    def get(name):
        return headers.get(name) or headers.get(name.lower())

    request_bound = get("X-Cloud-Request-Bound")
    if not request_bound:
        return verify_agent(headers, policy=policy, **kwargs)

    cloud_id = get("X-Cloud-ID")
    timestamp = get("X-Cloud-Timestamp")
    signature = get("X-Cloud-Signature")

    # Run basic checks (without signature verification)
    basic = verify_agent(headers, policy=policy, **kwargs)
    if not basic.get("verified") and basic.get("reason") != "invalid_signature":
        return basic

    agent_data = basic.get("agent")
    if not agent_data:
        return _result(False, "invalid_cloud_id", start=start)

    # Verify request-bound signature
    try:
        public_key = serialization.load_pem_public_key(
            agent_data["public_key"].encode("utf-8")
        )
        body_hash = _base64url_encode(
            hashlib.sha256((body or "").encode("utf-8")).digest()
        )
        payload = f"{cloud_id}:{timestamp}:{method.upper()}:{url}:{body_hash}"
        sig_bytes = _base64url_decode(signature)
        public_key.verify(sig_bytes, payload.encode("utf-8"))
    except (InvalidSignature, Exception):
        return _result(False, "invalid_signature", agent=agent_data, start=start)

    return _result(True, agent=agent_data, timestamp=timestamp, start=start)


# ─── Convenience: cloud_fetch ─────────────────────────────────

def cloud_fetch(
    identity: CloudIdentity,
    url: str,
    method: str = "GET",
    body: Optional[str] = None,
    headers: Optional[dict] = None,
) -> dict:
    """
    Make an HTTP request with automatic Cloud Identity signing.

    Args:
        identity: The agent's CloudIdentity
        url: Request URL
        method: HTTP method
        body: Request body
        headers: Additional headers

    Returns:
        dict with 'status', 'headers', 'body' (parsed JSON or text)
    """
    all_headers = dict(headers or {})
    auth_headers = identity.sign_request(url, method, body or "")
    all_headers.update(auth_headers)

    data = body.encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, headers=all_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode("utf-8")
            try:
                resp_body = json.loads(resp_body)
            except (json.JSONDecodeError, ValueError):
                pass
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": resp_body,
            }
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode("utf-8")
        try:
            resp_body = json.loads(resp_body)
        except (json.JSONDecodeError, ValueError):
            pass
        return {
            "status": e.code,
            "headers": dict(e.headers),
            "body": resp_body,
        }


# ─── Internal helpers ─────────────────────────────────────────

import base64


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _fetch_json(url: str, timeout: int = 10) -> dict:
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise RegistryError(f"Registry returned {resp.status}")
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"verified": False}
        raise RegistryError(f"Registry returned {e.code}")
    except urllib.error.URLError as e:
        raise RegistryError(f"Cannot reach registry: {e}")


def _result(
    verified: bool,
    reason: str = None,
    agent: dict = None,
    timestamp: str = None,
    start: float = None,
) -> dict:
    r = {"verified": verified}
    if reason:
        r["reason"] = reason
    if agent:
        r["agent"] = agent
    if timestamp:
        r["timestamp"] = timestamp
    if start:
        r["latency"] = round((time.time() - start) * 1000, 1)
    return r
