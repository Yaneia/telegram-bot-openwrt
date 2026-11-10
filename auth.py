import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Dict, Any, Optional, Set, List
from urllib.parse import parse_qsl


@dataclass
class AuthUser:
    user_id: int
    first_name: str = ""
    last_name: str = ""
    username: str = ""
    role: str = "unauthorized"  # "admin" | "user" | "unauthorized"

    @property
    def is_authorized(self) -> bool:
        return self.role in ("admin", "user")

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "username": self.username,
            "role": self.role,
            "is_authorized": self.is_authorized,
            "is_admin": self.is_admin,
        }


class AccessManager:
    """
    Manages whitelisted users and role-based access control (RBAC) shared
    between the Telegram Bot and the Telegram Mini App API.
    """

    def __init__(self, whitelist_file: str, admin_user_ids: Set[int]):
        self.whitelist_file = whitelist_file
        self.admin_user_ids: Set[int] = set(admin_user_ids)
        self.whitelisted_users: Set[int] = self._load_whitelist()

    def _load_whitelist(self) -> Set[int]:
        if not os.path.exists(self.whitelist_file):
            return set()
        with open(self.whitelist_file, "r", encoding="utf-8") as f:
            return {int(line.strip()) for line in f if line.strip().isdigit()}

    def save_whitelist(self) -> None:
        with open(self.whitelist_file, "w", encoding="utf-8") as f:
            for uid in sorted(self.whitelisted_users):
                f.write(f"{uid}\n")

    def reload(self) -> None:
        self.whitelisted_users = self._load_whitelist()

    def get_role(self, user_id: Optional[int]) -> str:
        if user_id is None:
            return "unauthorized"
        if user_id in self.admin_user_ids:
            return "admin"
        if user_id in self.whitelisted_users:
            return "user"
        return "unauthorized"

    def is_authorized(self, user_id: Optional[int]) -> bool:
        return self.get_role(user_id) in ("admin", "user")

    def is_admin(self, user_id: Optional[int]) -> bool:
        return self.get_role(user_id) == "admin"

    def add_user(self, user_id: int) -> bool:
        already = user_id in self.whitelisted_users
        self.whitelisted_users.add(user_id)
        self.save_whitelist()
        return not already

    def remove_user(self, user_id: int) -> bool:
        if user_id in self.whitelisted_users:
            self.whitelisted_users.remove(user_id)
            self.save_whitelist()
            return True
        return False

    def list_users(self) -> List[Dict[str, Any]]:
        all_ids = sorted(self.whitelisted_users | self.admin_user_ids)
        return [
            {
                "user_id": uid,
                "role": "admin" if uid in self.admin_user_ids else "user",
                "in_whitelist_file": uid in self.whitelisted_users,
                "is_config_admin": uid in self.admin_user_ids,
            }
            for uid in all_ids
        ]


def verify_telegram_init_data(
    init_data: str,
    bot_token: str,
    max_age_sec: int = 86400,
) -> Optional[Dict[str, Any]]:
    """
    Validate Telegram WebApp.initData string using HMAC-SHA256 per Telegram docs:
    https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
    Returns parsed user dict if valid, or None if invalid/expired.
    """
    if not init_data or not bot_token:
        return None

    parsed = dict(parse_qsl(init_data, keep_blank_values=True))
    received_hash = parsed.pop("hash", None)
    if not received_hash:
        return None

    # Check auth_date freshness if max_age_sec > 0
    if max_age_sec > 0:
        auth_date_str = parsed.get("auth_date", "0")
        if not auth_date_str.isdigit():
            return None
        auth_date = int(auth_date_str)
        if abs(time.time() - auth_date) > max_age_sec:
            return None

    data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(parsed.items()))
    secret_key = hmac.new(
        b"WebAppData",
        bot_token.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    calculated_hash = hmac.new(
        secret_key,
        data_check_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(calculated_hash, received_hash):
        return None

    user_raw = parsed.get("user")
    if not user_raw:
        return None

    try:
        user_data = json.loads(user_raw)
        if not isinstance(user_data, dict) or "id" not in user_data:
            return None
        return user_data
    except ValueError:
        return None
