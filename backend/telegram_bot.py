from __future__ import annotations

import html
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from config import load_settings
from service import VcamService, parse_iso


MENU_MARKUP = {
    "keyboard": [
        [{"text": "/users"}, {"text": "/status"}],
        [{"text": "/find user"}, {"text": "/add user pass 30d"}],
        [{"text": "/clear user"}, {"text": "/del user"}],
        [{"text": "/delexpired"}, {"text": "/help"}],
    ],
    "resize_keyboard": True,
    "one_time_keyboard": False,
}


def parse_duration(raw: str) -> timedelta:
    value = raw.strip().lower()
    if not value:
        raise ValueError("empty duration")

    suffix = value[-1]
    if suffix in {"m", "h", "d"}:
        amount = int(value[:-1])
        if amount <= 0:
            raise ValueError("invalid duration")
        if suffix == "m":
            return timedelta(minutes=amount)
        if suffix == "h":
            return timedelta(hours=amount)
        return timedelta(days=amount)

    amount = int(value)
    if amount <= 0:
        raise ValueError("invalid duration")
    return timedelta(days=amount)


def remaining_text(expires_at: Optional[str]) -> str:
    expiry = parse_iso(expires_at)
    if not expiry:
        return "N/A"
    remaining = expiry - datetime.now()
    if remaining.total_seconds() <= 0:
        return "Het han"
    days = remaining.days
    hours = remaining.seconds // 3600
    minutes = (remaining.seconds % 3600) // 60
    return f"{days}d {hours}h {minutes}m"


class TelegramBot:
    def __init__(self) -> None:
        self.settings = load_settings()
        self.service = VcamService(self.settings)
        self.offset = 0
        if not self.settings.telegram_bot_token:
            raise RuntimeError("Missing VCAM_TELEGRAM_BOT_TOKEN")
        if not self.settings.telegram_admin_ids:
            raise RuntimeError("Missing VCAM_TELEGRAM_ADMIN_IDS")

    def api_call(self, method: str, payload: Optional[Dict] = None):
        url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/{method}"
        data = None
        headers = {}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=35) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError:
            return None

    def send_message(self, chat_id: int, text: str, include_menu: bool = True) -> None:
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
        if include_menu:
            payload["reply_markup"] = MENU_MARKUP
        self.api_call("sendMessage", payload)

    def get_updates(self) -> List[Dict]:
        payload = {"timeout": 30, "offset": self.offset + 1}
        result = self.api_call("getUpdates", payload)
        if not result or not result.get("ok"):
            return []
        return result.get("result", [])

    def is_admin(self, chat_id: int) -> bool:
        return chat_id in self.settings.telegram_admin_ids

    def help_text(self) -> str:
        return (
            "<b>VCAM Admin Bot</b>\n"
            "/users [page]\n"
            "/find &lt;user&gt;\n"
            "/add &lt;user&gt; &lt;pass&gt; &lt;duration&gt; [max_devices] [timeout_seconds]\n"
            "/extend &lt;user&gt; &lt;duration&gt;\n"
            "/clear &lt;user&gt;\n"
            "/del &lt;user&gt;\n"
            "/setmax &lt;user&gt; &lt;count&gt;\n"
            "/settimeout &lt;user&gt; &lt;seconds&gt;\n"
            "/delexpired\n"
            "/status"
        )

    def list_users_text(self, page: int = 1, per_page: int = 20) -> str:
        page = max(1, page)
        offset = (page - 1) * per_page
        rows = self.service.list_users(limit=per_page, offset=offset)
        total = self.service.count_users()
        if not rows:
            return "Khong co user nao."

        lines = [f"<b>Users</b> page {page}"]
        for row in rows:
            lines.append(
                f"<code>{html.escape(row['username'])}</code> | "
                f"<code>{html.escape(row['password'])}</code> | "
                f"{remaining_text(row['expires_at'])} | "
                f"{int(row['max_devices'])} may | {int(row['timeout_seconds'])}s"
            )
        lines.append(f"Total: <b>{total}</b>")
        return "\n".join(lines)

    def user_detail_text(self, username: str) -> str:
        user, sessions = self.service.get_user_detail(username)
        if not user:
            return f"Khong tim thay user <code>{html.escape(username)}</code>."

        lines = [
            "<b>User detail</b>",
            f"User: <code>{html.escape(user['username'])}</code>",
            f"Pass: <code>{html.escape(user['password'])}</code>",
            f"Expires: <code>{html.escape(user['expires_at'] or '')}</code>",
            f"Remain: <b>{remaining_text(user['expires_at'])}</b>",
            f"Max devices: <b>{int(user['max_devices'])}</b>",
            f"Timeout: <b>{int(user['timeout_seconds'])}s</b>",
            f"Login count: <b>{int(user['login_count'])}</b>",
        ]
        if sessions:
            lines.append("Devices:")
            now = time.time()
            for item in sessions:
                seen_ago = int(now - float(item["last_seen"]))
                lines.append(
                    f"- <code>{html.escape(item['device_id'])}</code> | "
                    f"<code>{html.escape(item['ip'])}</code> | {seen_ago}s ago"
                )
        return "\n".join(lines)

    def status_text(self) -> str:
        status = self.service.get_status()
        return (
            "<b>VCAM Status</b>\n"
            f"Users: <b>{status['user_count']}</b>\n"
            f"Online users: <b>{status['active_user_count']}</b>\n"
            f"Active devices: <b>{status['active_device_count']}</b>\n"
            f"Time: <code>{datetime.now().isoformat(timespec='seconds')}</code>"
        )

    def handle_command(self, chat_id: int, text: str) -> None:
        command = text.strip()
        if command in {"/start", "/help", "menu"}:
            self.send_message(chat_id, self.help_text())
            return

        parts = command.split()
        if not parts:
            self.send_message(chat_id, self.help_text())
            return

        head = parts[0].lower()
        if head == "/users":
            page = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
            self.send_message(chat_id, self.list_users_text(page))
            return

        if head == "/find" and len(parts) >= 2:
            self.send_message(chat_id, self.user_detail_text(parts[1]))
            return

        if head == "/add" and len(parts) >= 4:
            max_devices = int(parts[4]) if len(parts) >= 5 else None
            timeout_seconds = int(parts[5]) if len(parts) >= 6 else None
            action, user = self.service.create_or_extend_user(
                parts[1],
                parts[2],
                parse_duration(parts[3]),
                max_devices=max_devices,
                timeout_seconds=timeout_seconds,
            )
            self.send_message(
                chat_id,
                f"User <code>{html.escape(user['username'])}</code> {action}.\n"
                f"Pass: <code>{html.escape(user['password'])}</code>\n"
                f"Expires: <code>{html.escape(user['expires_at'])}</code>",
            )
            return

        if head == "/extend" and len(parts) >= 3:
            user = self.service.find_user(parts[1])
            if not user:
                self.send_message(chat_id, f"Khong tim thay user <code>{html.escape(parts[1])}</code>.")
                return
            action, updated = self.service.create_or_extend_user(
                user["username"],
                user["password"],
                parse_duration(parts[2]),
                max_devices=int(user["max_devices"]),
                timeout_seconds=int(user["timeout_seconds"]),
            )
            self.send_message(
                chat_id,
                f"User <code>{html.escape(updated['username'])}</code> {action}.\n"
                f"Expires: <code>{html.escape(updated['expires_at'])}</code>",
            )
            return

        if head == "/clear" and len(parts) >= 2:
            if self.service.clear_user_devices(parts[1]):
                self.send_message(chat_id, f"Da clear thiet bi cho <code>{html.escape(parts[1])}</code>.")
            else:
                self.send_message(chat_id, f"Khong tim thay user <code>{html.escape(parts[1])}</code>.")
            return

        if head == "/del" and len(parts) >= 2:
            if self.service.delete_user(parts[1]):
                self.send_message(chat_id, f"Da xoa user <code>{html.escape(parts[1])}</code>.")
            else:
                self.send_message(chat_id, f"Khong tim thay user <code>{html.escape(parts[1])}</code>.")
            return

        if head == "/delexpired":
            expired = self.service.delete_expired_users()
            if not expired:
                self.send_message(chat_id, "Khong co user het han.")
                return
            preview = "\n".join(f"- <code>{html.escape(name)}</code>" for name in expired[:20])
            suffix = ""
            if len(expired) > 20:
                suffix = f"\n... va them {len(expired) - 20} user"
            self.send_message(chat_id, f"Da xoa {len(expired)} user het han.\n{preview}{suffix}")
            return

        if head == "/setmax" and len(parts) >= 3:
            updated = self.service.set_limits(parts[1], max_devices=int(parts[2]))
            if updated:
                self.send_message(chat_id, f"Updated max_devices for <code>{html.escape(updated['username'])}</code> -> <b>{int(updated['max_devices'])}</b>")
            else:
                self.send_message(chat_id, f"Khong tim thay user <code>{html.escape(parts[1])}</code>.")
            return

        if head == "/settimeout" and len(parts) >= 3:
            updated = self.service.set_limits(parts[1], timeout_seconds=int(parts[2]))
            if updated:
                self.send_message(chat_id, f"Updated timeout for <code>{html.escape(updated['username'])}</code> -> <b>{int(updated['timeout_seconds'])}s</b>")
            else:
                self.send_message(chat_id, f"Khong tim thay user <code>{html.escape(parts[1])}</code>.")
            return

        if head == "/status":
            self.send_message(chat_id, self.status_text())
            return

        self.send_message(chat_id, self.help_text())

    def handle_update(self, update: Dict) -> None:
        self.offset = max(self.offset, int(update.get("update_id", 0)))
        message = update.get("message") or {}
        chat = message.get("chat") or {}
        chat_id = int(chat.get("id", 0))
        text = str(message.get("text") or "").strip()
        if not chat_id or not text:
            return
        if not self.is_admin(chat_id):
            self.send_message(chat_id, "Unauthorized.", include_menu=False)
            return
        self.handle_command(chat_id, text)

    def run(self) -> None:
        while True:
            updates = self.get_updates()
            for update in updates:
                self.handle_update(update)
            time.sleep(1)


if __name__ == "__main__":
    TelegramBot().run()
