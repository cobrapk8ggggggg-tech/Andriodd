"""Short-lived, conversation-scoped access. Never expose the signing key to iOS."""
import base64
import hashlib
import hmac
import json
import time


def encode(key, owner, conversation, role="viewer", ttl=300, now=None):
    if len(key) < 32 or role not in {"viewer", "agent"}: raise ValueError("Invalid laboratory signing configuration")
    raw = json.dumps({"sub": owner, "conversation": conversation, "role": role,
                      "exp": int(now or time.time()) + min(max(ttl, 1), 300)}, separators=(",", ":")).encode()
    payload = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return payload + "." + hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()


def decode(key, token, now=None):
    try:
        payload, signature = token.split(".")
        if len(token) > 2000 or len(key) < 32 or not hmac.compare_digest(
            signature, hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()): raise ValueError()
        value = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if value["role"] not in {"viewer", "agent"} or not isinstance(value["exp"], int) or not 0 < value["exp"] - (now or time.time()) <= 301: raise ValueError()
        if not all(isinstance(value[x], str) and 0 < len(value[x]) <= 100 for x in ["sub", "conversation"]): raise ValueError()
        return value
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        raise ValueError("Expired or invalid laboratory access") from None
