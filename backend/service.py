from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from config import Settings


DEFAULT_DENY_MESSAGE = "Sai tk hoặc mật khẩu nhắn admin để biết thêm"
DEFAULT_EXPIRED_MESSAGE = "Tài khoản của bạn đã hết hạn."
DEFAULT_DEVICE_LIMIT_MESSAGE = "Đang quá tải máy vui lòng chờ {remaining} giây."


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


class VcamService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db_path = Path(settings.db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY COLLATE NOCASE,
                    password TEXT NOT NULL,
                    created_at TEXT,
                    expires_at TEXT,
                    max_devices INTEGER NOT NULL DEFAULT 1,
                    timeout_seconds INTEGER NOT NULL DEFAULT 300,
                    last_login_at TEXT,
                    login_count INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS device_sessions (
                    username TEXT NOT NULL COLLATE NOCASE,
                    device_id TEXT NOT NULL,
                    ip TEXT NOT NULL DEFAULT '',
                    last_seen REAL NOT NULL,
                    PRIMARY KEY (username, device_id),
                    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_device_sessions_username_seen
                ON device_sessions (username, last_seen);

                CREATE TABLE IF NOT EXISTS auth_tokens (
                    token TEXT PRIMARY KEY,
                    username TEXT NOT NULL COLLATE NOCASE,
                    device_id TEXT NOT NULL,
                    signing_key TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked_at REAL,
                    last_verified REAL,
                    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_auth_tokens_username
                ON auth_tokens (username);
                """
            )

    def list_users(self, limit: int = 50, offset: int = 0):
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT username, password, created_at, expires_at, max_devices,
                       timeout_seconds, last_login_at, login_count
                FROM users
                ORDER BY lower(username) ASC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        return rows

    def count_users(self) -> int:
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def find_user(self, username: Optional[str]):
        if not username:
            return None
        with self._connect() as conn:
            return conn.execute(
                """
                SELECT username, password, created_at, expires_at, max_devices,
                       timeout_seconds, last_login_at, login_count
                FROM users
                WHERE lower(username) = lower(?)
                LIMIT 1
                """,
                (username.strip(),),
            ).fetchone()

    def get_user_detail(self, username: str):
        user = self.find_user(username)
        if not user:
            return None, []
        with self._connect() as conn:
            sessions = conn.execute(
                """
                SELECT device_id, ip, last_seen
                FROM device_sessions
                WHERE lower(username) = lower(?)
                ORDER BY last_seen DESC
                """,
                (user["username"],),
            ).fetchall()
        return user, sessions

    def get_status(self) -> Dict[str, int]:
        now = time.time()
        with self._connect() as conn:
            user_count = int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])
            active_user_count = int(
                conn.execute(
                    """
                    SELECT COUNT(DISTINCT username)
                    FROM device_sessions
                    WHERE last_seen >= ?
                    """,
                    (now - self.settings.default_timeout_seconds,),
                ).fetchone()[0]
            )
            active_device_count = int(
                conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM device_sessions
                    WHERE last_seen >= ?
                    """,
                    (now - self.settings.default_timeout_seconds,),
                ).fetchone()[0]
            )
        return {
            "user_count": user_count,
            "active_user_count": active_user_count,
            "active_device_count": active_device_count,
        }

    def _user_is_expired(self, user: sqlite3.Row) -> bool:
        expires_at = parse_iso(user["expires_at"])
        return bool(expires_at and datetime.now() > expires_at)

    def _password_matches(self, stored_password: str, provided_password: Optional[str]) -> bool:
        if provided_password is None:
            return False
        stored = str(stored_password or "")
        provided = str(provided_password or "")
        provided_lower = provided.lower()
        expected_md5 = hashlib.md5(stored.encode("utf-8")).hexdigest().lower()
        return (
            provided == stored
            or provided_lower == stored.lower()
            or provided_lower == expected_md5
        )

    def _touch_login(self, conn: sqlite3.Connection, username: str) -> None:
        conn.execute(
            """
            UPDATE users
            SET last_login_at = ?, login_count = COALESCE(login_count, 0) + 1
            WHERE lower(username) = lower(?)
            """,
            (datetime.now().isoformat(), username),
        )

    def _enforce_device_pool(
        self,
        conn: sqlite3.Connection,
        user: sqlite3.Row,
        client_ip: str,
        client_id: Optional[str],
        touch_login: bool,
    ):
        username = user["username"]
        if self._user_is_expired(user):
            return False, DEFAULT_EXPIRED_MESSAGE

        if not client_id:
            if touch_login:
                self._touch_login(conn, username)
            return True, "OK"

        max_devices = int(user["max_devices"] or self.settings.default_max_devices)
        timeout_seconds = int(user["timeout_seconds"] or self.settings.default_timeout_seconds)
        now = time.time()

        rows = conn.execute(
            """
            SELECT username, device_id, ip, last_seen
            FROM device_sessions
            WHERE lower(username) = lower(?)
            ORDER BY last_seen ASC
            """,
            (username,),
        ).fetchall()

        active_rows = []
        existing_row = None
        stale_rows = []
        for row in rows:
            if row["device_id"] == client_id:
                existing_row = row
                continue
            if now - float(row["last_seen"]) < timeout_seconds:
                active_rows.append(row)
            else:
                stale_rows.append(row)

        for row in stale_rows:
            conn.execute(
                """
                DELETE FROM device_sessions
                WHERE lower(username) = lower(?) AND device_id = ?
                """,
                (username, row["device_id"]),
            )

        if existing_row:
            conn.execute(
                """
                INSERT INTO device_sessions (username, device_id, ip, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(username, device_id)
                DO UPDATE SET ip = excluded.ip, last_seen = excluded.last_seen
                """,
                (username, client_id, client_ip, now),
            )
            if touch_login:
                self._touch_login(conn, username)
            return True, "OK"

        if len(active_rows) >= max_devices:
            oldest = active_rows[0]
            elapsed = now - float(oldest["last_seen"])
            if elapsed < timeout_seconds:
                remaining = max(1, int(timeout_seconds - elapsed))
                return False, DEFAULT_DEVICE_LIMIT_MESSAGE.format(remaining=remaining)

            conn.execute(
                """
                DELETE FROM device_sessions
                WHERE lower(username) = lower(?) AND device_id = ?
                """,
                (username, oldest["device_id"]),
            )

        conn.execute(
            """
            INSERT INTO device_sessions (username, device_id, ip, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(username, device_id)
            DO UPDATE SET ip = excluded.ip, last_seen = excluded.last_seen
            """,
            (username, client_id, client_ip, now),
        )
        if touch_login:
            self._touch_login(conn, username)
        return True, "OK"

    def authenticate_password(
        self,
        username: Optional[str],
        password: Optional[str],
        client_ip: str,
        client_id: Optional[str],
        touch_login: bool = True,
    ):
        user = self.find_user(username)
        if not user or not self._password_matches(user["password"], password):
            return False, DEFAULT_DENY_MESSAGE, None

        with self._connect() as conn:
            current = conn.execute(
                """
                SELECT username, password, created_at, expires_at, max_devices,
                       timeout_seconds, last_login_at, login_count
                FROM users
                WHERE lower(username) = lower(?)
                LIMIT 1
                """,
                (user["username"],),
            ).fetchone()
            ok, message = self._enforce_device_pool(conn, current, client_ip, client_id, touch_login)
            refreshed = conn.execute(
                """
                SELECT username, password, created_at, expires_at, max_devices,
                       timeout_seconds, last_login_at, login_count
                FROM users
                WHERE lower(username) = lower(?)
                LIMIT 1
                """,
                (user["username"],),
            ).fetchone()
            return ok, message, refreshed

    def authenticate_known_user(
        self,
        username: Optional[str],
        client_ip: str,
        client_id: Optional[str],
        touch_login: bool = False,
    ):
        user = self.find_user(username)
        if not user:
            return False, DEFAULT_DENY_MESSAGE, None

        with self._connect() as conn:
            current = conn.execute(
                """
                SELECT username, password, created_at, expires_at, max_devices,
                       timeout_seconds, last_login_at, login_count
                FROM users
                WHERE lower(username) = lower(?)
                LIMIT 1
                """,
                (user["username"],),
            ).fetchone()
            ok, message = self._enforce_device_pool(conn, current, client_ip, client_id, touch_login)
            refreshed = conn.execute(
                """
                SELECT username, password, created_at, expires_at, max_devices,
                       timeout_seconds, last_login_at, login_count
                FROM users
                WHERE lower(username) = lower(?)
                LIMIT 1
                """,
                (user["username"],),
            ).fetchone()
            return ok, message, refreshed

    def issue_modern_token(self, username: str, device_id: Optional[str]) -> Dict[str, object]:
        user = self.find_user(username)
        if not user:
            raise ValueError("user_not_found")

        device_id = device_id or ""
        token = f"{user['username']}_{int(time.time() * 1000)}_{secrets.token_hex(8)}"
        signing_key = secrets.token_hex(32)
        issued_at = time.time()
        expires_at = issued_at + self.settings.modern_token_ttl_seconds

        user_expiry = parse_iso(user["expires_at"])
        if user_expiry:
            expires_at = min(expires_at, user_expiry.timestamp())

        with self._connect() as conn:
            conn.execute(
                "DELETE FROM auth_tokens WHERE lower(username) = lower(?) AND device_id = ?",
                (user["username"], device_id),
            )
            conn.execute(
                """
                INSERT INTO auth_tokens (token, username, device_id, signing_key, issued_at, expires_at, revoked_at, last_verified)
                VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
                """,
                (token, user["username"], device_id, signing_key, issued_at, expires_at),
            )

        return {
            "token": token,
            "signing_key": signing_key,
            "expires_at": expires_at,
            "username": user["username"],
        }

    def verify_modern_token(
        self,
        token: Optional[str],
        device_id: Optional[str],
        client_ip: str,
    ):
        if not token:
            return False, "missing_token", None

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT token, username, device_id, signing_key, issued_at, expires_at, revoked_at, last_verified
                FROM auth_tokens
                WHERE token = ?
                LIMIT 1
                """,
                (token,),
            ).fetchone()

            if not row or row["revoked_at"] is not None:
                return False, "invalid_token", None

            if float(row["expires_at"]) <= time.time():
                conn.execute("DELETE FROM auth_tokens WHERE token = ?", (token,))
                return False, "token_expired", None

            effective_device = device_id or row["device_id"]
            if row["device_id"] and effective_device and row["device_id"] != effective_device:
                return False, "device_mismatch", None

            user = conn.execute(
                """
                SELECT username, password, created_at, expires_at, max_devices,
                       timeout_seconds, last_login_at, login_count
                FROM users
                WHERE lower(username) = lower(?)
                LIMIT 1
                """,
                (row["username"],),
            ).fetchone()
            if not user:
                return False, "user_not_found", None

            ok, message = self._enforce_device_pool(conn, user, client_ip, effective_device, False)
            if not ok:
                return False, message, None

            conn.execute(
                "UPDATE auth_tokens SET last_verified = ? WHERE token = ?",
                (time.time(), token),
            )
            return True, "ok", user

    def logout_modern_token(self, token: Optional[str], device_id: Optional[str]) -> None:
        if not token:
            return
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT username, device_id
                FROM auth_tokens
                WHERE token = ?
                LIMIT 1
                """,
                (token,),
            ).fetchone()
            conn.execute("DELETE FROM auth_tokens WHERE token = ?", (token,))
            if row:
                session_device_id = device_id or row["device_id"]
                if session_device_id:
                    conn.execute(
                        """
                        DELETE FROM device_sessions
                        WHERE lower(username) = lower(?) AND device_id = ?
                        """,
                        (row["username"], session_device_id),
                    )

    def create_or_extend_user(
        self,
        username: str,
        password: str,
        delta: timedelta,
        max_devices: Optional[int] = None,
        timeout_seconds: Optional[int] = None,
    ):
        username = username.strip()
        password = password.strip()
        now = datetime.now()
        current = self.find_user(username)

        if current:
            current_expiry = parse_iso(current["expires_at"])
            base = current_expiry if current_expiry and current_expiry > now else now
            expires_at = (base + delta).isoformat()
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE users
                    SET password = ?, expires_at = ?, max_devices = ?, timeout_seconds = ?
                    WHERE lower(username) = lower(?)
                    """,
                    (
                        password,
                        expires_at,
                        int(max_devices or current["max_devices"] or self.settings.default_max_devices),
                        int(timeout_seconds or current["timeout_seconds"] or self.settings.default_timeout_seconds),
                        current["username"],
                    ),
                )
            action = "extended"
        else:
            expires_at = (now + delta).isoformat()
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO users (
                        username, password, created_at, expires_at, max_devices,
                        timeout_seconds, last_login_at, login_count
                    )
                    VALUES (?, ?, ?, ?, ?, ?, NULL, 0)
                    """,
                    (
                        username,
                        password,
                        now.isoformat(),
                        expires_at,
                        int(max_devices or self.settings.default_max_devices),
                        int(timeout_seconds or self.settings.default_timeout_seconds),
                    ),
                )
            action = "created"

        refreshed = self.find_user(username)
        if not refreshed:
            raise RuntimeError("failed_to_create_or_extend_user")
        return action, refreshed

    def clear_user_devices(self, username: str) -> bool:
        user = self.find_user(username)
        if not user:
            return False
        with self._connect() as conn:
            conn.execute("DELETE FROM device_sessions WHERE lower(username) = lower(?)", (user["username"],))
            conn.execute("DELETE FROM auth_tokens WHERE lower(username) = lower(?)", (user["username"],))
        return True

    def delete_user(self, username: str) -> bool:
        user = self.find_user(username)
        if not user:
            return False
        with self._connect() as conn:
            conn.execute("DELETE FROM users WHERE lower(username) = lower(?)", (user["username"],))
        return True

    def delete_expired_users(self) -> List[str]:
        expired: List[str] = []
        now = datetime.now()
        with self._connect() as conn:
            rows = conn.execute("SELECT username, expires_at FROM users").fetchall()
            for row in rows:
                expires_at = parse_iso(row["expires_at"])
                if expires_at and expires_at <= now:
                    expired.append(row["username"])
            for username in expired:
                conn.execute("DELETE FROM users WHERE lower(username) = lower(?)", (username,))
        expired.sort(key=str.lower)
        return expired

    def set_limits(self, username: str, max_devices: Optional[int] = None, timeout_seconds: Optional[int] = None):
        user = self.find_user(username)
        if not user:
            return None
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE users
                SET max_devices = ?, timeout_seconds = ?
                WHERE lower(username) = lower(?)
                """,
                (
                    int(max_devices or user["max_devices"] or self.settings.default_max_devices),
                    int(timeout_seconds or user["timeout_seconds"] or self.settings.default_timeout_seconds),
                    user["username"],
                ),
            )
        return self.find_user(user["username"])

    def import_user(self, username: str, payload: Dict[str, object]) -> None:
        created_at = str(payload.get("created") or payload.get("created_at") or datetime.now().isoformat())
        expires_at = str(payload.get("expires") or payload.get("expires_at") or "")
        password = str(payload.get("password") or "")
        max_devices = int(payload.get("max_devices") or self.settings.default_max_devices)
        timeout_seconds = int(payload.get("timeout") or payload.get("timeout_seconds") or self.settings.default_timeout_seconds)
        last_login_at = str(payload.get("last_login") or payload.get("last_login_at") or "") or None
        login_count = int(payload.get("login_count") or 0)

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO users (
                    username, password, created_at, expires_at, max_devices,
                    timeout_seconds, last_login_at, login_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    password = excluded.password,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at,
                    max_devices = excluded.max_devices,
                    timeout_seconds = excluded.timeout_seconds,
                    last_login_at = excluded.last_login_at,
                    login_count = excluded.login_count
                """,
                (
                    username,
                    password,
                    created_at,
                    expires_at,
                    max_devices,
                    timeout_seconds,
                    last_login_at,
                    login_count,
                ),
            )

    def import_device_session(self, username: str, session: Dict[str, object]) -> None:
        user = self.find_user(username)
        if not user:
            return
        device_id = str(session.get("id") or session.get("device_id") or "")
        if not device_id:
            return
        ip = str(session.get("ip") or "")
        seen = float(session.get("seen") or time.time())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO device_sessions (username, device_id, ip, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(username, device_id) DO UPDATE SET
                    ip = excluded.ip,
                    last_seen = excluded.last_seen
                """,
                (user["username"], device_id, ip, seen),
            )

    def wipe_all(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM auth_tokens")
            conn.execute("DELETE FROM device_sessions")
            conn.execute("DELETE FROM users")
