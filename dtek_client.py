import logging
import os
import sqlite3
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

log = logging.getLogger("dtek_client")

DEFAULT_CANDIDATE_DB_PATHS = [
    "/opt/telegram_bot_dtek/data/bot.db",
    "/opt/telegram_bot_dtek/data/dtek_bot.sqlite3",
    "/opt/telegram-bot-dtek/data/bot.db",
    "/root/telegram_bot_dtek/data/bot.db",
    "/srv/telegram_bot_dtek/data/bot.db",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "telegram_bot_dtek", "data", "bot.db")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "telegram_bot_dtek", "data", "dtek_bot.sqlite3")),
]


class DtekError(Exception):
    pass


@dataclass
class DtekConfig:
    db_path: str = ""
    enabled: bool = True


class DtekClient:
    """
    Read-only SQLite analytics client for telegram_bot_dtek (Ukrainian Outage Tracker).
    Reads WAL SQLite database in read-only URI mode (?mode=ro) without locking the bot.
    """

    def __init__(self, cfg: DtekConfig):
        self.cfg = cfg

    def resolve_db_path(self) -> Optional[str]:
        if self.cfg.db_path:
            expanded = os.path.expanduser(self.cfg.db_path)
            if os.path.isfile(expanded):
                return expanded
            return expanded  # Return configured path so error message is clear
        for candidate in DEFAULT_CANDIDATE_DB_PATHS:
            if os.path.isfile(candidate):
                return candidate
        return None

    def is_available(self) -> bool:
        if not self.cfg.enabled:
            return False
        path = self.resolve_db_path()
        return bool(path and os.path.isfile(path))

    def _connect_ro(self, db_path: str) -> sqlite3.Connection:
        uri = f"file:{os.path.abspath(db_path)}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=3.0)
        conn.row_factory = sqlite3.Row
        return conn

    def get_stats(self) -> Dict[str, Any]:
        db_path = self.resolve_db_path()
        if not db_path or not os.path.isfile(db_path):
            raise DtekError(
                f"База данных ДТЕК-бота не найдена ({db_path or 'укажите dtek.db_path в settings.yaml'})"
            )

        try:
            conn = self._connect_ro(db_path)
        except Exception as e:
            raise DtekError(f"Не удалось открыть SQLite базу ДТЕК ({db_path}): {e}") from e

        try:
            with conn:
                tables_rows = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
                ).fetchall()
                tables = {r["name"] for r in tables_rows}

                has_usage_events = "usage_events" in tables

                # 1. Users overview
                total_users = 0
                active_users = 0
                dau_24h = 0
                wau_7d = 0
                new_24h = 0
                new_7d = 0

                if "users" in tables:
                    row = conn.execute(
                        """
                        SELECT
                            COUNT(*) AS total,
                            SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) AS active,
                            SUM(CASE WHEN updated_at >= datetime('now', '-24 hours') THEN 1 ELSE 0 END) AS dau,
                            SUM(CASE WHEN updated_at >= datetime('now', '-7 days') THEN 1 ELSE 0 END) AS wau,
                            SUM(CASE WHEN created_at >= datetime('now', '-24 hours') THEN 1 ELSE 0 END) AS new_24h,
                            SUM(CASE WHEN created_at >= datetime('now', '-7 days') THEN 1 ELSE 0 END) AS new_7d
                        FROM users;
                        """
                    ).fetchone()
                    if row:
                        total_users = int(row["total"] or 0)
                        active_users = int(row["active"] or 0)
                        dau_24h = int(row["dau"] or 0)
                        wau_7d = int(row["wau"] or 0)
                        new_24h = int(row["new_24h"] or 0)
                        new_7d = int(row["new_7d"] or 0)

                # 2. Usage events / click counters (when usage_events table is enabled in DTEK bot)
                clicks_total = 0
                clicks_24h = 0
                clicks_7d = 0
                top_actions: List[Dict[str, Any]] = []
                user_clicks_map: Dict[int, Dict[str, Any]] = {}

                if has_usage_events:
                    c_row = conn.execute(
                        """
                        SELECT
                            COUNT(*) AS total,
                            SUM(CASE WHEN created_at >= datetime('now', '-24 hours') THEN 1 ELSE 0 END) AS c24h,
                            SUM(CASE WHEN created_at >= datetime('now', '-7 days') THEN 1 ELSE 0 END) AS c7d,
                            COUNT(DISTINCT CASE WHEN created_at >= datetime('now', '-24 hours') THEN user_id END) AS u24h,
                            COUNT(DISTINCT CASE WHEN created_at >= datetime('now', '-7 days') THEN user_id END) AS u7d
                        FROM usage_events;
                        """
                    ).fetchone()
                    if c_row:
                        clicks_total = int(c_row["total"] or 0)
                        clicks_24h = int(c_row["c24h"] or 0)
                        clicks_7d = int(c_row["c7d"] or 0)
                        dau_24h = max(dau_24h, int(c_row["u24h"] or 0))
                        wau_7d = max(wau_7d, int(c_row["u7d"] or 0))

                    action_rows = conn.execute(
                        """
                        SELECT
                            action,
                            COALESCE(event_type, 'command') AS event_type,
                            COUNT(*) AS total,
                            SUM(CASE WHEN created_at >= datetime('now', '-24 hours') THEN 1 ELSE 0 END) AS last_24h,
                            COUNT(DISTINCT user_id) AS unique_users
                        FROM usage_events
                        GROUP BY action
                        ORDER BY total DESC
                        LIMIT 12;
                        """
                    ).fetchall()
                    for ar in action_rows:
                        top_actions.append({
                            "action": str(ar["action"]),
                            "event_type": str(ar["event_type"]),
                            "total": int(ar["total"] or 0),
                            "last_24h": int(ar["last_24h"] or 0),
                            "unique_users": int(ar["unique_users"] or 0),
                        })

                    u_click_rows = conn.execute(
                        """
                        SELECT
                            user_id,
                            COUNT(*) AS total,
                            SUM(CASE WHEN created_at >= datetime('now', '-24 hours') THEN 1 ELSE 0 END) AS c24h,
                            MAX(created_at) AS last_seen
                        FROM usage_events
                        GROUP BY user_id;
                        """
                    ).fetchall()
                    for ucr in u_click_rows:
                        user_clicks_map[int(ucr["user_id"])] = {
                            "clicks_total": int(ucr["total"] or 0),
                            "clicks_24h": int(ucr["c24h"] or 0),
                            "last_seen": str(ucr["last_seen"] or ""),
                        }

                # 3. Slots & Regions breakdown
                total_slots = 0
                users_with_slots = 0
                dual_slot_users = 0
                regions: List[Dict[str, Any]] = []
                top_queues: List[Dict[str, Any]] = []
                slots_by_user: Dict[int, List[str]] = {}

                if "user_slots" in tables:
                    s_row = conn.execute(
                        """
                        SELECT
                            COUNT(*) AS total_slots,
                            COUNT(DISTINCT user_id) AS users_with_slots
                        FROM user_slots;
                        """
                    ).fetchone()
                    if s_row:
                        total_slots = int(s_row["total_slots"] or 0)
                        users_with_slots = int(s_row["users_with_slots"] or 0)

                    d_row = conn.execute(
                        """
                        SELECT COUNT(*) AS dual_cnt FROM (
                            SELECT user_id FROM user_slots GROUP BY user_id HAVING COUNT(*) >= 2
                        );
                        """
                    ).fetchone()
                    if d_row:
                        dual_slot_users = int(d_row["dual_cnt"] or 0)

                    reg_rows = conn.execute(
                        """
                        SELECT
                            region_code,
                            COUNT(*) AS slots_cnt,
                            COUNT(DISTINCT user_id) AS users_cnt
                        FROM user_slots
                        GROUP BY region_code
                        ORDER BY slots_cnt DESC;
                        """
                    ).fetchall()
                    for rr in reg_rows:
                        regions.append({
                            "region": str(rr["region_code"]),
                            "slots": int(rr["slots_cnt"] or 0),
                            "users": int(rr["users_cnt"] or 0),
                        })

                    q_rows = conn.execute(
                        """
                        SELECT
                            region_code,
                            subgroup_id,
                            COUNT(DISTINCT user_id) AS subscribers
                        FROM user_slots
                        GROUP BY region_code, subgroup_id
                        ORDER BY subscribers DESC, region_code ASC, subgroup_id ASC
                        LIMIT 8;
                        """
                    ).fetchall()
                    for qr in q_rows:
                        top_queues.append({
                            "region": str(qr["region_code"]),
                            "subgroup": str(qr["subgroup_id"]),
                            "subscribers": int(qr["subscribers"] or 0),
                        })

                    all_slot_rows = conn.execute(
                        "SELECT user_id, slot_number, region_code, subgroup_id, alias FROM user_slots ORDER BY slot_number ASC;"
                    ).fetchall()
                    for sr in all_slot_rows:
                        uid = int(sr["user_id"])
                        slots_by_user.setdefault(uid, []).append(
                            f"{sr['region_code']} {sr['subgroup_id']}"
                        )

                # 4. Notification settings & dispatched history
                notif_settings = {
                    "notify_30m": 0,
                    "notify_15m": 0,
                    "notify_diff": 0,
                }
                if "notification_settings" in tables:
                    ns_row = conn.execute(
                        """
                        SELECT
                            SUM(CASE WHEN notify_30m = 1 THEN 1 ELSE 0 END) AS n30,
                            SUM(CASE WHEN notify_15m = 1 THEN 1 ELSE 0 END) AS n15,
                            SUM(CASE WHEN notify_schedule_change = 1 THEN 1 ELSE 0 END) AS ndiff
                        FROM notification_settings;
                        """
                    ).fetchone()
                    if ns_row:
                        notif_settings = {
                            "notify_30m": int(ns_row["n30"] or 0),
                            "notify_15m": int(ns_row["n15"] or 0),
                            "notify_diff": int(ns_row["ndiff"] or 0),
                        }

                sent_total = 0
                sent_24h = 0
                sent_7d = 0
                sent_by_type: Dict[str, int] = {}

                if "notification_history" in tables:
                    nh_row = conn.execute(
                        """
                        SELECT
                            COUNT(*) AS total,
                            SUM(CASE WHEN sent_at >= datetime('now', '-24 hours') THEN 1 ELSE 0 END) AS s24h,
                            SUM(CASE WHEN sent_at >= datetime('now', '-7 days') THEN 1 ELSE 0 END) AS s7d
                        FROM notification_history;
                        """
                    ).fetchone()
                    if nh_row:
                        sent_total = int(nh_row["total"] or 0)
                        sent_24h = int(nh_row["s24h"] or 0)
                        sent_7d = int(nh_row["s7d"] or 0)

                    nt_rows = conn.execute(
                        "SELECT event_type, COUNT(*) AS cnt FROM notification_history GROUP BY event_type;"
                    ).fetchall()
                    for ntr in nt_rows:
                        sent_by_type[str(ntr["event_type"])] = int(ntr["cnt"] or 0)

                # 5. Scraper Schedule Cache health
                cache_list: List[Dict[str, Any]] = []
                if "schedule_cache" in tables:
                    sc_rows = conn.execute(
                        """
                        SELECT
                            region_code,
                            schedule_date,
                            is_emergency,
                            data_source,
                            updated_at
                        FROM schedule_cache
                        ORDER BY region_code ASC;
                        """
                    ).fetchall()
                    for scr in sc_rows:
                        cache_list.append({
                            "region": str(scr["region_code"]),
                            "date": str(scr["schedule_date"] or ""),
                            "emergency": bool(scr["is_emergency"]),
                            "source": str(scr["data_source"] or ""),
                            "updated_at": str(scr["updated_at"] or ""),
                        })

                # 6. Top / Recent users list (up to 15)
                recent_users: List[Dict[str, Any]] = []
                if "users" in tables:
                    u_rows = conn.execute(
                        """
                        SELECT user_id, username, first_name, is_active, created_at, updated_at
                        FROM users
                        ORDER BY updated_at DESC
                        LIMIT 25;
                        """
                    ).fetchall()
                    for ur in u_rows:
                        uid = int(ur["user_id"])
                        c_info = user_clicks_map.get(uid, {})
                        recent_users.append({
                            "user_id": uid,
                            "username": str(ur["username"] or ""),
                            "first_name": str(ur["first_name"] or ""),
                            "active": bool(ur["is_active"]),
                            "updated_at": str(c_info.get("last_seen") or ur["updated_at"] or ""),
                            "slots": slots_by_user.get(uid, []),
                            "clicks_total": int(c_info.get("clicks_total", 0)),
                            "clicks_24h": int(c_info.get("clicks_24h", 0)),
                        })
                    if has_usage_events:
                        recent_users.sort(
                            key=lambda u: (u["clicks_24h"], u["clicks_total"], u["updated_at"]),
                            reverse=True,
                        )
                    recent_users = recent_users[:15]

                return {
                    "configured": True,
                    "ok": True,
                    "has_usage_events": has_usage_events,
                    "users": {
                        "total": total_users,
                        "active": active_users,
                        "dau_24h": dau_24h,
                        "wau_7d": wau_7d,
                        "new_24h": new_24h,
                        "new_7d": new_7d,
                        "with_slots": users_with_slots,
                        "dual_slot": dual_slot_users,
                    },
                    "clicks": {
                        "total": clicks_total,
                        "last_24h": clicks_24h,
                        "last_7d": clicks_7d,
                        "top_actions": top_actions,
                    },
                    "slots": {
                        "total": total_slots,
                        "regions": regions,
                        "top_queues": top_queues,
                    },
                    "notifications": {
                        "settings": notif_settings,
                        "sent_total": sent_total,
                        "sent_24h": sent_24h,
                        "sent_7d": sent_7d,
                        "by_type": sent_by_type,
                    },
                    "cache": cache_list,
                    "recent_users": recent_users,
                }
        finally:
            conn.close()
