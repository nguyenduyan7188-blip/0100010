from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple


BASE_DIR = Path(__file__).resolve().parent


def _read_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _env(name: str, default: str, file_values: Dict[str, str]) -> str:
    return os.environ.get(name, file_values.get(name, default))


def _parse_admin_ids(value: str) -> Tuple[int, ...]:
    result = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        result.append(int(item))
    return tuple(result)


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    db_path: Path
    server_domain: str
    legacy_aes_key: bytes
    shared_hmac_hex: str
    ed25519_private_key_pem: str
    modern_token_ttl_seconds: int
    max_timestamp_skew_seconds: int
    default_max_devices: int
    default_timeout_seconds: int
    telegram_bot_token: str
    telegram_admin_ids: Tuple[int, ...]


def load_settings(env_path: Optional[Path] = None) -> Settings:
    env_file = env_path or BASE_DIR / ".env"
    file_values = _read_env_file(env_file)

    db_path_raw = _env("VCAM_DB_PATH", "./data/vcam.db", file_values)
    db_path = Path(db_path_raw)
    if not db_path.is_absolute():
        db_path = (BASE_DIR / db_path).resolve()

    private_key = _env("VCAM_ED25519_PRIVATE_KEY_PEM", "", file_values).replace("\\n", "\n")

    return Settings(
        host=_env("VCAM_HOST", "127.0.0.1", file_values),
        port=int(_env("VCAM_PORT", "5005", file_values)),
        db_path=db_path,
        server_domain=_env("VCAM_SERVER_DOMAIN", "nickerliii.xyz", file_values),
        legacy_aes_key=_env("VCAM_LEGACY_AES_KEY", "VCAM9#iOS3d#wKEK", file_values).encode("utf-8"),
        shared_hmac_hex=_env(
            "VCAM_SHARED_HMAC_HEX",
            "3636b322bc8c67fc9fd3899240c9865627b7a981d626efb9f154026baab8682e",
            file_values,
        ).lower(),
        ed25519_private_key_pem=private_key,
        modern_token_ttl_seconds=int(_env("VCAM_MODERN_TOKEN_TTL_SECONDS", "2592000", file_values)),
        max_timestamp_skew_seconds=int(_env("VCAM_MAX_TIMESTAMP_SKEW_SECONDS", "300", file_values)),
        default_max_devices=int(_env("VCAM_DEFAULT_MAX_DEVICES", "1", file_values)),
        default_timeout_seconds=int(_env("VCAM_DEFAULT_TIMEOUT_SECONDS", "300", file_values)),
        telegram_bot_token=_env("VCAM_TELEGRAM_BOT_TOKEN", "", file_values),
        telegram_admin_ids=_parse_admin_ids(_env("VCAM_TELEGRAM_ADMIN_IDS", "", file_values)),
    )
