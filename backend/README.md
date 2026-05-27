# VCAM Compat Backend

One SQLite database, two client protocols, one Telegram CRUD bot.

## What it supports

- Legacy VCAM client flow:
  - `POST /`
  - `POST /user/login`
  - wildcard legacy paths
  - AES/plain payload parsing compatible with the old Flask server
- New repo client flow:
  - `POST /login`
  - `POST /verify`
  - `POST /logout`
  - `X-Timestamp`, `X-Nonce`, `X-Signature`
  - signed responses with `server_sig` and `ed25519_sig`
- Telegram admin bot against the same SQLite DB
- Migration from legacy `vcam_users.json` and `vcam_sessions.json`

## Files

- `app.py`: Flask app with both protocol layers
- `service.py`: shared user/device/token logic on SQLite
- `telegram_bot.py`: Telegram CRUD bot
- `migrate_legacy_json.py`: imports old JSON data
- `deploy/`: systemd and nginx templates

## Quick Start

1. Copy `.env.example` to `.env`
2. Edit Telegram values if you want the new bot
3. Install deps:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

4. Import legacy data:

```bash
python migrate_legacy_json.py \
  --users-json /home/ubuntu/vcam_users.json \
  --sessions-json /home/ubuntu/vcam_sessions.json
```

5. Run backend:

```bash
gunicorn --workers 2 --bind 127.0.0.1:5005 --timeout 30 app:app
```

6. Run bot:

```bash
python telegram_bot.py
```

## Deploy Notes

- Point nginx `443`, `5003`, and `5004` to `127.0.0.1:5005`
- The repo client public key in `Shared/VcamConstants.h` matches the development private key in `.env.example`
- Rotate the Ed25519 private key before production and update `kVCEd25519PubKeyHex` to match

## Legacy JSON Import

Use `--wipe` if you want to replace existing SQLite data:

```bash
python migrate_legacy_json.py \
  --users-json /home/ubuntu/vcam_users.json \
  --sessions-json /home/ubuntu/vcam_sessions.json \
  --wipe
```
