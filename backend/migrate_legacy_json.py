from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict

from config import load_settings
from service import VcamService


def load_json(path: Path) -> Dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser(description="Import legacy VCAM JSON data into SQLite.")
    parser.add_argument("--users-json", required=True, help="Path to legacy vcam_users.json")
    parser.add_argument("--sessions-json", required=True, help="Path to legacy vcam_sessions.json")
    parser.add_argument("--env-file", default=None, help="Optional backend .env path")
    parser.add_argument("--wipe", action="store_true", help="Delete current SQLite data before import")
    args = parser.parse_args()

    settings = load_settings(Path(args.env_file) if args.env_file else None)
    service = VcamService(settings)

    if args.wipe:
        service.wipe_all()

    users = load_json(Path(args.users_json))
    sessions = load_json(Path(args.sessions_json))

    imported_users = 0
    for username, payload in users.items():
        if not isinstance(payload, dict):
            continue
        service.import_user(str(username), payload)
        imported_users += 1

    imported_sessions = 0
    for username, items in sessions.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            service.import_device_session(str(username), item)
            imported_sessions += 1

    print(f"Imported users: {imported_users}")
    print(f"Imported sessions: {imported_sessions}")
    print(f"SQLite DB: {settings.db_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
