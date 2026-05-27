from __future__ import annotations

import time

from flask import Flask, jsonify, request

from config import load_settings
from crypto_utils import ModernCrypto
from legacy_protocol import legacy_fail, legacy_success, parse_legacy_request
from service import DEFAULT_DENY_MESSAGE, VcamService


def create_app() -> Flask:
    settings = load_settings()
    service = VcamService(settings)
    modern_crypto = ModernCrypto(
        settings.shared_hmac_hex,
        settings.ed25519_private_key_pem,
        settings.max_timestamp_skew_seconds,
    )

    app = Flask(__name__)
    app.config["JSON_AS_ASCII"] = False

    def client_ip() -> str:
        return (
            request.headers.get("X-Real-IP")
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote_addr
            or ""
        )

    def modern_error(message: str, status_code: int = 400):
        return jsonify({"error": message}), status_code

    def signed_response(payload: dict, status_code: int = 200):
        payload.setdefault("server_ts", int(time.time()))
        payload.setdefault("nonce_echo", request.headers.get("X-Nonce", ""))
        return jsonify(modern_crypto.build_signed_response(payload)), status_code

    @app.route("/health", methods=["GET"])
    def health():
        status = service.get_status()
        return jsonify(
            {
                "status": "ok",
                "server_domain": settings.server_domain,
                "db_path": str(settings.db_path),
                "users": status["user_count"],
                "active_users": status["active_user_count"],
                "active_devices": status["active_device_count"],
                "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
        )

    @app.route("/login", methods=["POST"])
    def modern_login():
        body = request.get_data()
        ok, reason = modern_crypto.verify_request(
            request.path,
            body,
            request.headers.get("X-Timestamp"),
            request.headers.get("X-Signature"),
        )
        if not ok:
            return modern_error(reason, 401)

        payload = request.get_json(force=True, silent=True) or {}
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "").strip()
        device_id = str(payload.get("device_id") or payload.get("device_fingerprint") or "").strip() or None

        auth_ok, message, user = service.authenticate_password(username, password, client_ip(), device_id, touch_login=True)
        if not auth_ok or not user:
            return modern_error(message or DEFAULT_DENY_MESSAGE, 401)

        token_payload = service.issue_modern_token(user["username"], device_id)
        return signed_response(
            {
                "token": token_payload["token"],
                "signing_key": token_payload["signing_key"],
                "valid": True,
            }
        )

    @app.route("/verify", methods=["POST"])
    def modern_verify():
        body = request.get_data()
        ok, reason = modern_crypto.verify_request(
            request.path,
            body,
            request.headers.get("X-Timestamp"),
            request.headers.get("X-Signature"),
        )
        if not ok:
            return modern_error(reason, 401)

        payload = request.get_json(force=True, silent=True) or {}
        token = str(payload.get("token") or "").strip()
        device_id = str(payload.get("device_id") or "").strip() or None
        verified, message, _user = service.verify_modern_token(token, device_id, client_ip())
        if verified:
            return signed_response({"valid": True})
        return signed_response({"valid": False, "reason": message}, 401)

    @app.route("/logout", methods=["POST"])
    def modern_logout():
        body = request.get_data()
        ok, reason = modern_crypto.verify_request(
            request.path,
            body,
            request.headers.get("X-Timestamp"),
            request.headers.get("X-Signature"),
        )
        if not ok:
            return modern_error(reason, 401)

        payload = request.get_json(force=True, silent=True) or {}
        token = str(payload.get("token") or "").strip()
        device_id = str(payload.get("device_id") or "").strip() or None
        service.logout_modern_token(token, device_id)
        return signed_response({"ok": True})

    def handle_legacy():
        username, password, device_id = parse_legacy_request(request, settings.legacy_aes_key)
        if not username:
            return jsonify(legacy_fail(DEFAULT_DENY_MESSAGE))

        if password:
            ok, message, user = service.authenticate_password(username, password, client_ip(), device_id, touch_login=True)
        else:
            ok, message, user = service.authenticate_known_user(username, client_ip(), device_id, touch_login=False)

        if ok and user:
            return jsonify(legacy_success(user["username"]))
        return jsonify(legacy_fail(message or DEFAULT_DENY_MESSAGE))

    @app.route("/", methods=["GET", "POST", "PUT", "DELETE"])
    def legacy_root():
        return handle_legacy()

    @app.route("/user/login", methods=["GET", "POST", "PUT"])
    def legacy_login():
        return handle_legacy()

    @app.route("/<path:_path>", methods=["GET", "POST", "PUT", "DELETE"])
    def legacy_catchall(_path: str):
        return handle_legacy()

    return app


app = create_app()


if __name__ == "__main__":
    settings = load_settings()
    app.run(host=settings.host, port=settings.port, debug=False)
