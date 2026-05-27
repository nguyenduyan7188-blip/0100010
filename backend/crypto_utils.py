from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict, Union

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa


def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def hmac_hex(secret_bytes: bytes, payload: Union[str, bytes]) -> str:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return hmac.new(secret_bytes, payload, hashlib.sha256).hexdigest()


class ModernCrypto:
    def __init__(self, shared_hmac_hex: str, ed25519_private_key_pem: str, max_skew_seconds: int) -> None:
        self.shared_hmac_bytes = bytes.fromhex(shared_hmac_hex)
        self.max_skew_seconds = max_skew_seconds
        self.private_key = ECC.import_key(ed25519_private_key_pem) if ed25519_private_key_pem else None

    def verify_request(self, path: str, body: bytes, timestamp: str = None, signature: str = None):
        if not timestamp or not signature:
            return False, "missing_signature_headers"

        try:
            sent_ts = int(timestamp)
        except (TypeError, ValueError):
            return False, "invalid_timestamp"

        if abs(int(time.time()) - sent_ts) > self.max_skew_seconds:
            return False, "stale_timestamp"

        body_b64 = base64.b64encode(body).decode("ascii")
        payload = f"{timestamp}|{path}|{body_b64}"
        expected = hmac_hex(self.shared_hmac_bytes, payload)

        if not hmac.compare_digest(signature.lower(), expected.lower()):
            return False, "invalid_signature"
        return True, "ok"

    def build_signed_response(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        response = dict(payload)
        response["server_sig"] = hmac_hex(self.shared_hmac_bytes, canonical_json_bytes(response))

        if not self.private_key:
            raise RuntimeError("Missing VCAM_ED25519_PRIVATE_KEY_PEM")

        signer = eddsa.new(self.private_key, "rfc8032")
        signed_bytes = signer.sign(canonical_json_bytes(response))
        response["ed25519_sig"] = base64.b64encode(signed_bytes).decode("ascii")
        return response
