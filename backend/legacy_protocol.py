from __future__ import annotations

import base64
import hashlib
import json
from urllib.parse import parse_qs, unquote
from typing import Optional, Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


DEVICE_ID_FIELDS = (
    "device_id",
    "deviceid",
    "deviceId",
    "deviceID",
    "device_uuid",
    "deviceUUID",
    "udid",
    "uuid",
    "openudid",
    "idfa",
    "idfv",
    "identifier_for_vendor",
    "identifierForVendor",
    "vendor_id",
    "vendorId",
    "machine_id",
    "machineid",
    "machineId",
    "hwid",
    "client_id",
    "clientid",
    "clientId",
    "unique_id",
    "uniqueId",
    "serial",
    "serial_number",
    "serialNumber",
    "hash",
    "device_hash",
    "deviceHash",
    "device_fingerprint",
    "deviceFingerprint",
)

DEVICE_ID_HEADERS = (
    "X-Device-ID",
    "X-Device-Id",
    "X-Client-ID",
    "X-Client-Id",
    "X-VCAM-Device",
    "X-Machine-ID",
    "X-HWID",
    "Device-ID",
    "Device-Id",
    "DeviceID",
    "UDID",
    "X-UDID",
    "HWID",
    "Client-ID",
    "Client-Id",
    "X-IDFV",
    "X-Unique-ID",
)

USERNAME_FIELDS = ("username", "user", "name", "account", "login", "userid", "uid", "u", "tk", "taikhoan", "tai_khoan")
PASSWORD_FIELDS = ("password", "pwd", "pass", "passwd", "p", "matkhau", "mat_khau", "pass_md5", "password_md5", "md5")
TOKEN_FIELDS = ("token", "access_token", "auth_token")


def robust_aes_decrypt(encrypted_data, key):
    try:
        try:
            if isinstance(encrypted_data, str):
                pad_len = 4 - (len(encrypted_data) % 4)
                if pad_len != 4:
                    encrypted_data += "=" * pad_len
            elif isinstance(encrypted_data, bytes):
                pad_len = 4 - (len(encrypted_data) % 4)
                if pad_len != 4:
                    encrypted_data += b"=" * pad_len
            encrypted_bytes = base64.b64decode(encrypted_data)
        except Exception:
            encrypted_bytes = encrypted_data

        try:
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted = cipher.decrypt(encrypted_bytes)
            try:
                decrypted = unpad(decrypted, AES.block_size)
            except ValueError:
                pass
            return decrypted.decode("utf-8")
        except Exception:
            pass

        try:
            iv = encrypted_bytes[:16] if len(encrypted_bytes) > 16 else b"\x00" * 16
            cipher_data = encrypted_bytes[16:] if len(encrypted_bytes) > 16 else encrypted_bytes
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(cipher_data), AES.block_size)
            return decrypted.decode("utf-8")
        except Exception:
            pass

        try:
            cipher = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
            decrypted = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
            return decrypted.decode("utf-8")
        except Exception:
            pass
    except Exception:
        return None
    return None


def build_client_id(value: str) -> str:
    digest = hashlib.sha256(str(value).strip().encode("utf-8")).hexdigest()[:20]
    return f"device:{digest}"


def _first_value(params, key):
    value = params.get(key)
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _norm_key(key: str) -> str:
    return "".join(ch for ch in str(key).lower() if ch.isalnum())


def _first_present(params, fields):
    wanted = {_norm_key(item) for item in fields}
    for key in fields:
        value = _first_value(params, key)
        if value:
            return value

    try:
        keys = list(params.keys())
    except Exception:
        keys = []

    for key in keys:
        if _norm_key(key) in wanted:
            value = _first_value(params, key)
            if value:
                return value
    return None


def _find_device_value(data, inside_device: bool = False):
    fields = DEVICE_ID_FIELDS + (("id", "uuid", "identifier") if inside_device else ())
    if hasattr(data, "keys"):
        direct = _first_present(data, fields)
        if direct:
            return direct

        try:
            keys = list(data.keys())
        except Exception:
            keys = []

        for key in keys:
            try:
                value = _first_value(data, key)
            except Exception:
                continue
            nested = inside_device or _norm_key(key) in ("device", "dev", "machine", "client", "phone", "iosdevice")
            if isinstance(value, (dict, list, tuple)):
                found = _find_device_value(value, nested)
                if found:
                    return found
    elif isinstance(data, (list, tuple)):
        for value in data:
            found = _find_device_value(value, inside_device)
            if found:
                return found
    return None


def _username_from_token(params) -> Optional[str]:
    token = _first_present(params, TOKEN_FIELDS)
    if not token:
        return None
    token = str(token)
    return token.split("_")[0] if "_" in token else token


def parse_legacy_request(req, aes_key: bytes) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    username = None
    password = None
    client_id = None

    def fill_from_params(params) -> None:
        nonlocal username, password, client_id
        username = username or _first_present(params, USERNAME_FIELDS)
        password = password or _first_present(params, PASSWORD_FIELDS)
        if not username:
            username = _username_from_token(params)
        if not client_id:
            value = _find_device_value(params)
            if value:
                client_id = build_client_id(value)

    def fill_from_dict(data) -> None:
        nonlocal username, password, client_id
        if not isinstance(data, dict):
            return
        username = username or _first_present(data, USERNAME_FIELDS)
        password = password or _first_present(data, PASSWORD_FIELDS)
        if not username:
            username = _username_from_token(data)
        if not client_id:
            value = _find_device_value(data)
            if value:
                client_id = build_client_id(value)

    raw_body = req.get_data()
    if raw_body:
        decrypted = robust_aes_decrypt(raw_body, aes_key)
        if decrypted:
            try:
                if "%3D" in decrypted or "%26" in decrypted:
                    decrypted = unquote(decrypted)
                params = parse_qs(decrypted)
                fill_from_params(params)
                if not username:
                    fill_from_dict(json.loads(decrypted))
            except Exception:
                pass
        else:
            try:
                decoded = unquote(raw_body.decode("utf-8", errors="ignore"))
                fill_from_params(parse_qs(decoded))
            except Exception:
                pass

    if not username:
        payload = req.get_json(force=True, silent=True)
        if payload:
            fill_from_dict(payload)

    if not username and req.form:
        fill_from_params(req.form)
    if not username and req.args:
        fill_from_params(req.args)

    if not client_id:
        for header in DEVICE_ID_HEADERS:
            header_value = req.headers.get(header)
            if header_value:
                client_id = build_client_id(header_value)
                break

    username = str(username).strip() if username is not None else None
    password = str(password).strip() if password is not None else None
    return username, password, client_id


def legacy_success(username: str):
    return {
        "code": 0,
        "txt": "OK",
        "valid": True,
        "config_port": 8080,
        "remaining_seconds": 3153600000,
        "token": f"{username}_{int(__import__('time').time() * 1000)}",
        "message": "Welcome VIP",
        "is_vip": True,
        "vip_level": 99,
        "unlimited_bandwidth": True,
        "watermark": False,
        "max_fps": 60,
        "max_resolution": "4K",
        "license": "PERMANENT",
    }


def legacy_fail(message: str):
    return {
        "code": -1,
        "txt": message,
        "valid": False,
        "message": message,
    }
