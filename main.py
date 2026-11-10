#!/usr/bin/env python3
import argparse
import asyncio
import base64
import json
import logging
import os
import yaml
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Tuple, Set, Optional

from wakeonlan import send_magic_packet

from adguard_client import AdGuardClient, AdGuardConfig, AdGuardError
from auth import AccessManager
from openwrt_client import OpenWrtClient, RouterConfig, OpenWrtError
from rpc_bridge import ServerlessRpcBridge, derive_rpc_credentials
from state_codec import (
    build_serverless_snapshot,
    encode_combined_snapshot_with_budget,
    encode_state_token,
    split_snapshot_into_app_tokens,
)
from unifi_client import UniFiClient, UniFiConfig, UniFiError
from webapp_server import WebAppServer

# ---------------- Logging ----------------
logging.basicConfig(
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    level=logging.INFO,
)
log = logging.getLogger("bot")

# ---------------- Paths & Settings ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WHITELIST_FILE = os.path.join(BASE_DIR, "whitelisted_users.txt")
SETTINGS_FILE = os.path.join(BASE_DIR, "settings.yaml")


def load_settings(settings_path: str = SETTINGS_FILE) -> Dict[str, Any]:
    if not os.path.exists(settings_path):
        raise RuntimeError(f"settings.yaml not found at {settings_path}")
    with open(settings_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    required = ["bot_token", "routers"]
    for k in required:
        if k not in data:
            raise RuntimeError(f"settings.yaml missing '{k}'")

    routers = data.get("routers") or {}
    if not isinstance(routers, dict) or not routers:
        raise RuntimeError("settings.yaml 'routers' must be a non-empty mapping")
    for name, rcfg in routers.items():
        for field in ("ip", "password"):
            if not rcfg.get(field):
                raise RuntimeError(f"settings.yaml router '{name}' is missing '{field}'")

    data.setdefault("wake_on_lan_hosts", {})
    data.setdefault("admin_user_ids", [])
    data.setdefault("webapp", {})
    return data


settings = load_settings()
adguard_cfg = settings.get("adguard")
ADGUARD: Optional[AdGuardClient] = None
ADGUARD_DEFAULT_DURATION_MS = 600000

if adguard_cfg and adguard_cfg.get("base_url"):
    timeout_cfg = adguard_cfg.get("timeout") or {}
    ADGUARD_DEFAULT_DURATION_MS = int(adguard_cfg.get("default_duration_ms", 600000))
    ADGUARD = AdGuardClient(
        AdGuardConfig(
            base_url=adguard_cfg["base_url"],
            username=adguard_cfg.get("username", ""),
            password=adguard_cfg.get("password", ""),
            verify_tls=bool(adguard_cfg.get("verify_tls", False)),
            timeout=(int(timeout_cfg.get("connect", 5)), int(timeout_cfg.get("read", 10))),
        )
    )

unifi_cfg = settings.get("unifi")
UNIFI: Optional[UniFiClient] = None
if unifi_cfg and (unifi_cfg.get("base_url") or unifi_cfg.get("username") or unifi_cfg.get("api_key")):
    raw_guest_wlans = unifi_cfg.get("guest_wlan_names") or []
    if isinstance(raw_guest_wlans, str):
        guest_wlans = [x.strip() for x in raw_guest_wlans.split(",") if x.strip()]
    else:
        guest_wlans = [str(x).strip() for x in raw_guest_wlans if x]
    UNIFI = UniFiClient(
        UniFiConfig(
            base_url=str(unifi_cfg.get("base_url") or "https://127.0.0.1:11443"),
            username=str(unifi_cfg.get("username") or ""),
            password=str(unifi_cfg.get("password") or ""),
            api_key=str(unifi_cfg.get("api_key") or ""),
            site=str(unifi_cfg.get("site") or "default"),
            verify_tls=bool(unifi_cfg.get("verify_tls", False)),
            is_unifi_os=unifi_cfg.get("is_unifi_os"),
            guest_wlan_names=guest_wlans,
        )
    )

BOT_TOKEN: str = settings["bot_token"]
wake_on_lan_hosts: Dict[str, Dict[str, str]] = settings["wake_on_lan_hosts"] or {}
ADMIN_USER_IDS: Set[int] = {int(x) for x in (settings.get("admin_user_ids") or [])}

# Shared Access / Whitelist Manager
access_manager = AccessManager(WHITELIST_FILE, ADMIN_USER_IDS)

# WebApp configuration
# By default, 'enabled' is False so NO port is opened on the router (100% Serverless mode via GitHub Pages + WebApp.sendData)
DEFAULT_GITHUB_PAGES_URL = "https://yaneia.github.io/telegram-bot-openwrt/"
webapp_cfg: Dict[str, Any] = settings.get("webapp") or {}
_raw_static_url = str(
    webapp_cfg.get("static_url")
    or webapp_cfg.get("public_url")
    or DEFAULT_GITHUB_PAGES_URL
).strip()
if _raw_static_url and not _raw_static_url.endswith("/") and not _raw_static_url.endswith(".html"):
    _raw_static_url += "/"
WEBAPP_STATIC_URL: str = _raw_static_url
WEBAPP_LOCAL_SERVER_ENABLED: bool = bool(webapp_cfg.get("enabled", False))
WEBAPP_HOST: str = str(webapp_cfg.get("host", "127.0.0.1"))
WEBAPP_PORT: int = int(webapp_cfg.get("port", 8080))
WEBAPP_DEV_MODE: bool = bool(
    webapp_cfg.get("dev_mode", False) or os.environ.get("TMA_DEV_MODE") == "1"
)
WEBAPP_DEV_USER_ID: Optional[int] = (
    int(webapp_cfg["dev_user_id"]) if webapp_cfg.get("dev_user_id") else None
)
CHAT_MENU_ENABLED: bool = bool(
    webapp_cfg.get("chat_menu_enabled", settings.get("chat_menu_enabled", False))
)
RPC_BRIDGE_ENABLED: bool = bool(webapp_cfg.get("rpc_bridge", True))
RPC_CREDS: Optional[Dict[str, str]] = (
    derive_rpc_credentials(BOT_TOKEN) if RPC_BRIDGE_ENABLED else None
)

# routers: { name: OpenWrtClient }
router_clients: Dict[str, OpenWrtClient] = {
    name: OpenWrtClient(
        RouterConfig(
            ip=rcfg["ip"],
            username=rcfg.get("username", "root"),
            password=rcfg["password"],
            verify_tls=rcfg.get("verify_tls", False),
            guest_network_device=rcfg.get("guest_network_device"),
        )
    )
    for name, rcfg in settings["routers"].items()
}

# Run blocking work in a thread (HTTP requests)
_executor = ThreadPoolExecutor(max_workers=8)

webapp_server = WebAppServer(
    bot_token=BOT_TOKEN,
    access_manager=access_manager,
    router_clients=router_clients,
    adguard_client=ADGUARD,
    adguard_default_duration_ms=ADGUARD_DEFAULT_DURATION_MS,
    wol_hosts=wake_on_lan_hosts,
    executor=_executor,
    host=WEBAPP_HOST,
    port=WEBAPP_PORT,
    dev_mode=WEBAPP_DEV_MODE,
    dev_user_id=WEBAPP_DEV_USER_ID,
)


async def run_blocking(func, *args, **kwargs):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, lambda: func(*args, **kwargs))


def _format_user_list() -> str:
    users = access_manager.list_users()
    if not users:
        return "Whitelist is empty."
    lines = [
        f"- {u['user_id']} ({'admin' if u['role'] == 'admin' else 'user'})"
        for u in users
    ]
    return "Authorized users:\n" + "\n".join(lines)


async def build_user_state_tokens(
    user,
    bot_username: str = "",
    max_per_button_len: int = 1650,
) -> Dict[str, str]:
    snapshot = await build_serverless_snapshot(
        user_id=user.id,
        first_name=user.first_name or "",
        username=user.username or "",
        access=access_manager,
        router_clients=router_clients,
        adguard=ADGUARD,
        wol_hosts=wake_on_lan_hosts,
        executor=_executor,
        bot_username=bot_username,
        unifi=UNIFI,
        rpc_creds=RPC_CREDS,
    )
    combined_tok = encode_combined_snapshot_with_budget(
        snapshot,
        max_len=max_per_button_len,
    )
    return {
        "combined": combined_tok,
        "home": combined_tok,
    }


async def handle_rpc_request(req_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle background RPC requests from the Mini App so button clicks never close the app
    and never post messages to the Telegram chat, and full client lists are returned without URL limits.
    """
    user_id = int(req_data.get("user_id") or 0)
    if not access_manager.is_authorized(user_id):
        return {"ok": False, "error": "Нет доступа."}

    action = str(req_data.get("action") or "")
    first_name = str(req_data.get("first_name") or "")
    username = str(req_data.get("username") or "")

    msg = ""
    if action and action != "get_state":
        msg = await execute_miniapp_command(user_id, req_data)

    fresh_snapshot = await build_serverless_snapshot(
        user_id=user_id,
        first_name=first_name,
        username=username,
        access=access_manager,
        router_clients=router_clients,
        adguard=ADGUARD,
        wol_hosts=wake_on_lan_hosts,
        executor=_executor,
        bot_username="",
        unifi=UNIFI,
        rpc_creds=RPC_CREDS,
    )
    return {
        "ok": True,
        "message": msg,
        "snapshot": fresh_snapshot,
    }


async def execute_miniapp_command(user_id: int, payload: Dict[str, Any]) -> str:
    """
    Execute an action sent from the Serverless Mini App (via WebApp.sendData or deep-link)
    with strict Role-Based Access Control (RBAC).
    """
    if not access_manager.is_authorized(user_id):
        return "⛔ Нет доступа."

    is_admin = access_manager.is_admin(user_id)
    action = str(payload.get("action") or "")

    if action == "refresh_state":
        return "🔄 Состояние пульта обновлено."

    # 1. Guest Wi-Fi Toggle (allowed for 'user' and 'admin')
    # Supports target: "all" (both OpenWrt + UniFi guest), "openwrt" (all OpenWrt routers), "unifi" (all UniFi guest WLANs), or a specific router name
    if action == "wifi_toggle":
        mode = str(payload.get("mode") or "off").lower()
        target_router = str(payload.get("router") or "all")
        if mode not in ("on", "off"):
            return "⚠️ Некорректный режим Wi-Fi."

        errors = []
        toggled_parts = []

        # 1a. Toggle on OpenWrt routers if target is "all", "openwrt", or a specific router name
        if target_router != "unifi":
            targets = (
                {target_router: router_clients[target_router]}
                if target_router not in ("all", "openwrt") and target_router in router_clients
                else router_clients
            )
            for rname, client in targets.items():
                try:
                    await run_blocking(client.toggle_guest_wifi, mode)
                    toggled_parts.append(f"OpenWrt ({rname})")
                except Exception as e:
                    errors.append(f"OpenWrt {rname}: {e}")

        # 1b. Toggle Guest WLANs in UniFi if target is "all" or "unifi"
        if target_router in ("all", "unifi") and UNIFI is not None:
            try:
                count = await run_blocking(UNIFI.toggle_guest_wlans, mode == "on")
                if count > 0:
                    toggled_parts.append("UniFi Guest")
            except Exception as e:
                errors.append(f"UniFi: {e}")

        label = "ВКЛЮЧЕН ✅" if mode == "on" else "ВЫКЛЮЧЕН 🌙"
        scope = " + ".join(toggled_parts) if toggled_parts else target_router
        if errors:
            return f"⚠️ Гостевой Wi-Fi {label} ({scope}), но с ошибками:\n" + "\n".join(errors)
        return f"📶 Гостевой Wi-Fi {label} ({scope})."

    # 2. AdGuard Toggle (allowed for 'user' and 'admin')
    if action == "adguard_toggle":
        if ADGUARD is None:
            return "⚠️ AdGuard Home не настроен в settings.yaml."
        enabled = bool(payload.get("enabled", True))
        duration_mins = payload.get("duration_minutes")
        duration_ms = (
            max(1, int(duration_mins)) * 60 * 1000
            if (not enabled and duration_mins)
            else (None if enabled else ADGUARD_DEFAULT_DURATION_MS)
        )
        try:
            await run_blocking(ADGUARD.set_protection, enabled, duration_ms)
            if enabled:
                return "🛡️ Защита AdGuard Home ВКЛЮЧЕНА ✅"
            mins = int((duration_ms or 0) / 60000)
            return f"⏸️ Защита AdGuard Home приостановлена на {mins} мин."
        except AdGuardError as e:
            return f"❌ Ошибка AdGuard: {e}"

    # 2b. UniFi WLAN Toggle (allowed for 'admin', or for 'user' if the WLAN is marked is_guest)
    if action == "unifi_wlan_toggle":
        if UNIFI is None:
            return "⚠️ UniFi Controller не настроен в settings.yaml."
        wlan_id = str(payload.get("wlan_id") or "").strip()
        wlan_name = str(payload.get("name") or wlan_id)
        enabled = bool(payload.get("enabled", True))
        try:
            if not is_admin:
                wlans = await run_blocking(UNIFI.get_wlans)
                matched = next((w for w in wlans if w["id"] == wlan_id), None)
                if not matched or not matched.get("is_guest"):
                    return "⛔ Обычным пользователям разрешено управлять только гостевыми сетями UniFi."
            await run_blocking(UNIFI.toggle_wlan, wlan_id, enabled)
            state_str = "ВКЛЮЧЕНА ✅" if enabled else "ВЫКЛЮЧЕНА 🌙"
            return f"🛜 Сеть UniFi «{wlan_name}» {state_str}."
        except UniFiError as e:
            return f"❌ Ошибка UniFi WLAN: {e}"

    # ---------------- Admin-Only Actions ----------------
    if not is_admin:
        return "⛔ Это действие доступно только администраторам."

    # 2c. UniFi Admin Actions (Restart AP/Switch, LED toggle, PoE cycle, Client kick/block)
    if action.startswith("unifi_"):
        if UNIFI is None:
            return "⚠️ UniFi Controller не настроен в settings.yaml."
        try:
            if action == "unifi_device_restart":
                mac = str(payload.get("mac") or "").strip()
                dname = str(payload.get("name") or mac)
                await run_blocking(UNIFI.restart_device, mac)
                return f"🔄 Перезагрузка точки/устройства UniFi «{dname}» запущена."
            if action == "unifi_device_led":
                dev_id = str(payload.get("device_id") or "").strip()
                mode = str(payload.get("mode") or "default").lower()
                dname = str(payload.get("name") or dev_id)
                await run_blocking(UNIFI.set_device_led, dev_id, mode)
                return f"💡 Индикатор LED на «{dname}» переключен в режим: {mode.upper()}."
            if action == "unifi_poe_cycle":
                mac = str(payload.get("mac") or "").strip()
                port_idx = int(payload.get("port_idx") or 0)
                pname = str(payload.get("name") or f"Port {port_idx}")
                await run_blocking(UNIFI.power_cycle_poe_port, mac, port_idx)
                return f"⚡ Перезагрузка питания PoE запущена на порту «{pname}»."
            if action == "unifi_client_kick":
                mac = str(payload.get("mac") or "").strip()
                cname = str(payload.get("hostname") or mac)
                await run_blocking(UNIFI.kick_client, mac)
                return f"🔄 Клиент «{cname}» переподключен (Kick)."
            if action == "unifi_client_block":
                mac = str(payload.get("mac") or "").strip()
                block = bool(payload.get("block", True))
                cname = str(payload.get("hostname") or mac)
                await run_blocking(UNIFI.set_client_block, mac, block)
                return f"🚫 Клиент «{cname}» {'ЗАБЛОКИРОВАН' if block else 'РАЗБЛОКИРОВАН'} в UniFi."
        except Exception as e:
            return f"❌ Ошибка UniFi: {e}"

    # 2d. Unified OpenWrt Router Client Management (Kick Wi-Fi, Block/Unblock WAN, Wake-on-LAN by MAC)
    if action == "client_kick":
        mac = str(payload.get("mac") or "").strip().lower()
        cname = str(payload.get("hostname") or mac)
        if not mac:
            return "⚠️ Не указан MAC клиента."
        for client in router_clients.values():
            try:
                await run_blocking(client.kick_wifi_client, mac)
            except Exception:
                pass
        if UNIFI is not None:
            try:
                await run_blocking(UNIFI.kick_client, mac)
            except Exception:
                pass
        return f"🔄 Клиент «{cname}» переподключен (Wi-Fi Kick)."

    if action == "client_block":
        mac = str(payload.get("mac") or "").strip().lower()
        block = bool(payload.get("block", True))
        cname = str(payload.get("hostname") or mac)
        if not mac:
            return "⚠️ Не указан MAC клиента."
        errors = []
        for rname, client in router_clients.items():
            try:
                await run_blocking(client.set_client_block, mac, block, cname)
            except Exception as e:
                errors.append(f"{rname}: {e}")
        state_lbl = "ЗАБЛОКИРОВАН 🚫" if block else "РАЗБЛОКИРОВАН ✅"
        if errors:
            return f"⚠️ Клиент «{cname}» {state_lbl}, но с ошибками: {'; '.join(errors)}"
        return f"🛡️ Доступ в интернет для «{cname}» ({mac}) {state_lbl}."

    if action == "client_wol":
        mac = str(payload.get("mac") or "").strip()
        cname = str(payload.get("hostname") or mac)
        if not mac:
            return "⚠️ Не указан MAC для WOL."
        try:
            await run_blocking(send_magic_packet, mac, ip_address="255.255.255.255")
            return f"⚡ Magic Packet (WOL) отправлен на «{cname}» ({mac})."
        except Exception as e:
            return f"❌ Ошибка WOL: {e}"

    # 3. Wake-on-LAN
    if action == "wol_wake":
        host_name = str(payload.get("host") or "").strip()
        host_cfg = wake_on_lan_hosts.get(host_name)
        if not host_cfg or not host_cfg.get("mac"):
            return f"⚠️ Хост '{host_name}' не найден или не задан MAC."
        ip_broadcast = host_cfg.get("ip") or "255.255.255.255"
        try:
            await run_blocking(send_magic_packet, host_cfg["mac"], ip_address=ip_broadcast)
            return f"⚡ Magic Packet отправлен на {host_name} ({host_cfg['mac']})."
        except Exception as e:
            return f"❌ Ошибка WOL для {host_name}: {e}"

    # 4. Router Reboot
    if action == "router_reboot":
        rname = str(payload.get("router") or "").strip()
        client = router_clients.get(rname)
        if not client:
            return f"⚠️ Роутер '{rname}' не найден."
        try:
            await run_blocking(client.reboot)
            return f"🔄 Команда перезагрузки отправлена на роутер {rname}."
        except OpenWrtError as e:
            return f"❌ Не удалось перезагрузить {rname}: {e}"

    # 5. Whitelist User Add / Remove
    if action == "user_add":
        raw_uid = str(payload.get("user_id") or "").strip()
        if not raw_uid.isdigit():
            return "⚠️ Некорректный Telegram ID."
        target_uid = int(raw_uid)
        access_manager.add_user(target_uid)
        return f"✅ Пользователь {target_uid} добавлен в белый список."

    if action == "user_remove":
        raw_uid = str(payload.get("user_id") or "").strip()
        if not raw_uid.isdigit():
            return "⚠️ Некорректный Telegram ID."
        target_uid = int(raw_uid)
        if access_manager.remove_user(target_uid):
            return f"🗑️ Пользователь {target_uid} удалён из белого списка."
        return f"⚠️ Пользователь {target_uid} не найден в файле белого списка."

    return f"⚠️ Неизвестная команда: {action}"


# ---------------- Telegram Bot Setup ----------------
def build_bot_application():
    from telegram import (
        Update,
        InlineKeyboardButton,
        InlineKeyboardMarkup,
        KeyboardButton,
        MenuButtonDefault,
        ReplyKeyboardMarkup,
        ReplyKeyboardRemove,
        WebAppInfo,
    )
    from telegram.error import BadRequest
    from telegram.ext import (
        Application,
        ApplicationBuilder,
        CommandHandler,
        CallbackQueryHandler,
        ContextTypes,
        MessageHandler,
        filters,
    )

    def create_reply_markup(rows: List[List[Tuple[str, str]]]) -> InlineKeyboardMarkup:
        return InlineKeyboardMarkup(
            [
                [InlineKeyboardButton(text, callback_data=data) for text, data in row]
                for row in rows
            ]
        )

    def _app_url(app_name: str, state_token: str) -> str:
        sep = "&" if "?" in WEBAPP_STATIC_URL else "?"
        return f"{WEBAPP_STATIC_URL}{sep}app={app_name}&state={state_token}"

    def build_reply_keyboard_from_tokens(
        user_id: int, tokens: Dict[str, str]
    ) -> Optional[ReplyKeyboardMarkup]:
        if not WEBAPP_STATIC_URL.startswith("https://") or not tokens:
            return None
        combined_tok = tokens.get("combined") or tokens.get("home") or ""
        rows: List[List[KeyboardButton]] = [
            [
                KeyboardButton(
                    "🎛️ Открыть пульт",
                    web_app=WebAppInfo(url=_app_url("home", combined_tok)),
                )
            ]
        ]
        util_row = [KeyboardButton("🔄 Обновить пульт")]
        if CHAT_MENU_ENABLED:
            util_row.append(KeyboardButton("📋 Меню в чате"))
        rows.append(util_row)
        return ReplyKeyboardMarkup(rows, resize_keyboard=True)

    async def safe_reply_with_keyboard(
        message,
        text: str,
        user,
        bot_username: str = "",
        tokens: Optional[Dict[str, str]] = None,
    ):
        if not WEBAPP_STATIC_URL.startswith("https://"):
            await message.reply_text(text)
            return None
        if tokens is None:
            tokens = await build_user_state_tokens(
                user, bot_username=bot_username, max_per_button_len=1650
            )
        reply_kb = build_reply_keyboard_from_tokens(user.id, tokens)
        try:
            await message.reply_text(text, reply_markup=reply_kb)
            return tokens
        except BadRequest as e:
            if "too long" in str(e).lower():
                log.warning("Reply markup exceeded limit (%s), retrying with compact budget...", e)
                tokens = await build_user_state_tokens(
                    user, bot_username=bot_username, max_per_button_len=1100
                )
                reply_kb = build_reply_keyboard_from_tokens(user.id, tokens)
                await message.reply_text(text, reply_markup=reply_kb)
                return tokens
            raise

    def build_inline_menu_markup(
        user_id: int, tokens: Optional[Dict[str, str]] = None
    ) -> InlineKeyboardMarkup:
        is_admin = access_manager.is_admin(user_id)
        button_rows: List[List[InlineKeyboardButton]] = []

        if WEBAPP_STATIC_URL.startswith("https://") and tokens:
            home_tok = tokens.get("home", "")
            button_rows.append(
                [
                    InlineKeyboardButton(
                        "🏠 Открыть Домашний пульт (App)",
                        web_app=WebAppInfo(url=_app_url("home", home_tok)),
                    )
                ]
            )
            if is_admin:
                inline_admin_row = [
                    InlineKeyboardButton(
                        "📡 Сеть и WOL (App)",
                        web_app=WebAppInfo(
                            url=_app_url("network", tokens.get("network", home_tok))
                        ),
                    ),
                ]
                if UNIFI is not None and "unifi" in tokens:
                    inline_admin_row.append(
                        InlineKeyboardButton(
                            "🛜 UniFi (App)",
                            web_app=WebAppInfo(url=_app_url("unifi", tokens["unifi"])),
                        )
                    )
                inline_admin_row.append(
                    InlineKeyboardButton(
                        "🔐 Доступ (App)",
                        web_app=WebAppInfo(
                            url=_app_url("admin", tokens.get("admin", home_tok))
                        ),
                    )
                )
                button_rows.append(inline_admin_row)

        button_rows.append(
            [
                InlineKeyboardButton("📶 WiFi", callback_data="menu_wifi"),
                InlineKeyboardButton("🛡️ AdGuard", callback_data="menu_system_adguard"),
            ]
        )
        if is_admin:
            button_rows.append(
                [
                    InlineKeyboardButton("⚙️ System & WOL", callback_data="menu_system"),
                    InlineKeyboardButton("🔐 Admin", callback_data="menu_admin"),
                ]
            )
        return InlineKeyboardMarkup(button_rows)

    async def ensure_authorized(update: Update) -> bool:
        user_id = update.effective_user.id if update.effective_user else None
        if not access_manager.is_authorized(user_id):
            target = update.message or (
                update.callback_query and update.callback_query.message
            )
            if target:
                await target.reply_text(
                    "You are not authorized to use this bot. Use /get_user_id to get your user ID.",
                    reply_markup=ReplyKeyboardRemove(),
                )
            return False
        return True

    async def ensure_admin(update: Update) -> bool:
        user_id = update.effective_user.id if update.effective_user else None
        if not access_manager.is_admin(user_id):
            if update.callback_query:
                await update.callback_query.answer("Admins only", show_alert=True)
            elif update.message:
                await update.message.reply_text("Admins only.")
            return False
        return True

    # ---------------- Commands & WebApp Data ----------------
    async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await ensure_authorized(update):
            return
        user = update.effective_user
        bot_username = context.bot.username or ""

        # Check if launched with deep-link command fallback (?start=cmd_<base64url>)
        if context.args and context.args[0].startswith("cmd_"):
            b64_part = context.args[0][4:]
            try:
                pad = "=" * ((4 - len(b64_part) % 4) % 4)
                payload = json.loads(
                    base64.urlsafe_b64decode((b64_part + pad).encode("ascii")).decode("utf-8")
                )
                result_msg = await execute_miniapp_command(user.id, payload)
                await safe_reply_with_keyboard(update.message, result_msg, user, bot_username)
                return
            except Exception as e:
                log.warning("Failed to parse deep-link cmd: %s", e)

        tokens = None
        if WEBAPP_STATIC_URL.startswith("https://"):
            tokens = await safe_reply_with_keyboard(
                update.message,
                "🔒 Пульт готов (работает без открытых портов на роутере).\n"
                "Откройте нужное приложение кнопкой на нижней клавиатуре:",
                user,
                bot_username,
            )
        if CHAT_MENU_ENABLED or not WEBAPP_STATIC_URL.startswith("https://"):
            await update.message.reply_text(
                "Меню управления:",
                reply_markup=build_inline_menu_markup(user.id, tokens),
            )

    async def cmd_app(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await ensure_authorized(update):
            return
        user = update.effective_user
        if not WEBAPP_STATIC_URL.startswith("https://"):
            await update.message.reply_text(
                "Укажите `webapp.static_url` (например, ссылку на ваш GitHub Pages) в `settings.yaml`."
            )
            return
        await safe_reply_with_keyboard(
            update.message,
            "🔄 Снимок состояния обновлён! Выберите приложение на нижней клавиатуре:",
            user,
            context.bot.username or "",
        )

    async def on_webapp_data(update: Update, context: ContextTypes.DEFAULT_TYPE):
        """
        Receives actions sent from the static Mini App via Telegram.WebApp.sendData().
        Executes them locally on OpenWrt/AdGuard and refreshes the Reply Keyboard state snapshot.
        """
        if not await ensure_authorized(update):
            return
        user = update.effective_user
        raw_data = update.effective_message.web_app_data.data
        try:
            payload = json.loads(raw_data)
        except ValueError:
            await update.message.reply_text("⚠️ Ошибка формата данных от Mini App.")
            return

        result_text = await execute_miniapp_command(user.id, payload)
        await safe_reply_with_keyboard(
            update.message, result_text, user, context.bot.username or ""
        )

    async def cmd_get_user_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
        uid = update.effective_user.id
        role = access_manager.get_role(uid)
        if role in ("admin", "user"):
            await update.message.reply_text(
                f"You're authorized ({role}) ✅\nYour user ID is {uid}."
            )
        else:
            await update.message.reply_text(
                "You're not authorized yet.\n"
                f"Share this user ID with an admin to get access: {uid}",
                reply_markup=ReplyKeyboardRemove(),
            )

    async def cmd_adduser(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await ensure_admin(update):
            return
        if len(context.args) != 1 or not context.args[0].isdigit():
            await update.message.reply_text("Usage: /adduser <user_id>")
            return
        uid = int(context.args[0])
        access_manager.add_user(uid)
        await update.message.reply_text(f"User {uid} added ✅")

    async def cmd_userdel(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await ensure_admin(update):
            return
        if len(context.args) != 1 or not context.args[0].isdigit():
            await update.message.reply_text("Usage: /userdel <user_id>")
            return
        uid = int(context.args[0])
        if access_manager.remove_user(uid):
            await update.message.reply_text(f"User {uid} removed ✅")
        else:
            await update.message.reply_text(f"User {uid} is not in the whitelist.")

    async def cmd_listusers(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await ensure_admin(update):
            return
        await update.message.reply_text(_format_user_list())

    async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if "awaiting_admin_action" in context.user_data:
            context.user_data.pop("awaiting_admin_action", None)
            await update.message.reply_text("Canceled.")

    # ---------------- Callback Query (buttons) ----------------
    async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
        q = update.callback_query
        await q.answer()
        data = q.data
        uid = update.effective_user.id if update.effective_user else 0

        if data == "menu_main":
            if not await ensure_authorized(update):
                return
            await q.edit_message_text(
                "Choose an option:", reply_markup=build_inline_menu_markup(uid)
            )
            return

        # WiFi
        if data == "menu_wifi":
            if not await ensure_authorized(update):
                return
            kb = create_reply_markup(
                [
                    [("Guest", "menu_wifi_guest")],
                    [("⬅️ Back", "menu_main")],
                ]
            )
            await q.edit_message_text("WiFi", reply_markup=kb)
            return

        if data == "menu_wifi_guest":
            if not await ensure_authorized(update):
                return
            kb = create_reply_markup(
                [
                    [("Enable", "wifi_guest_on"), ("Disable", "wifi_guest_off")],
                    [("⬅️ Back", "menu_wifi")],
                ]
            )
            await q.edit_message_text("Guest WiFi", reply_markup=kb)
            return

        if data in ("wifi_guest_on", "wifi_guest_off"):
            if not await ensure_authorized(update):
                return
            action = "on" if data.endswith("_on") else "off"
            errors = []
            for name, client in router_clients.items():
                try:
                    await run_blocking(client.toggle_guest_wifi, action)
                    log.info("Guest WiFi %s on %s OK", action, name)
                except OpenWrtError as e:
                    log.error("Guest WiFi %s on %s FAILED: %s", action, name, e)
                    errors.append(f"{name}: {e}")

            status = "ENABLED" if action == "on" else "DISABLED"
            suffix = (
                ""
                if not errors
                else "\n\nErrors:\n" + "\n".join(f"- {e}" for e in errors)
            )
            kb = create_reply_markup(
                [
                    [("Enable", "wifi_guest_on"), ("Disable", "wifi_guest_off")],
                    [("⬅️ Back", "menu_wifi_guest")],
                ]
            )
            await q.edit_message_text(
                f"Guest WiFi is now {status}.{suffix}", reply_markup=kb
            )
            return

        # AdGuard
        if data == "menu_system_adguard":
            if not await ensure_authorized(update):
                return
            back_target = "menu_system" if access_manager.is_admin(uid) else "menu_main"
            if ADGUARD is None:
                await q.edit_message_text(
                    "AdGuard is not configured (missing 'adguard' in settings.yaml).",
                    reply_markup=create_reply_markup([[("⬅️ Back", back_target)]]),
                )
                return

            kb = create_reply_markup(
                [
                    [
                        ("Protection ON", "adguard_prot_on"),
                        ("Protection OFF (10m)", "adguard_prot_off_10m"),
                    ],
                    [
                        ("Protection OFF (30m)", "adguard_prot_off_30m"),
                        ("Protection OFF (60m)", "adguard_prot_off_60m"),
                    ],
                    [("⬅️ Back", back_target)],
                ]
            )
            await q.edit_message_text("AdGuard Home", reply_markup=kb)
            return

        if data in (
            "adguard_prot_on",
            "adguard_prot_off_10m",
            "adguard_prot_off_30m",
            "adguard_prot_off_60m",
        ):
            if not await ensure_authorized(update):
                return
            if ADGUARD is None:
                await q.answer("AdGuard not configured", show_alert=True)
                return

            enabled = data == "adguard_prot_on"
            duration_ms = None
            if not enabled:
                if data.endswith("_10m"):
                    duration_ms = 10 * 60 * 1000
                elif data.endswith("_30m"):
                    duration_ms = 30 * 60 * 1000
                elif data.endswith("_60m"):
                    duration_ms = 60 * 60 * 1000
                else:
                    duration_ms = ADGUARD_DEFAULT_DURATION_MS

            try:
                await run_blocking(ADGUARD.set_protection, enabled, duration_ms)
                if enabled:
                    msg = "AdGuard protection is now ENABLED ✅"
                else:
                    mins = int(duration_ms / 60000) if duration_ms else 0
                    msg = f"AdGuard protection is now DISABLED ⛔ for {mins} minutes."
            except AdGuardError as e:
                msg = f"Failed to change AdGuard protection: {e}"

            await q.edit_message_text(
                msg,
                reply_markup=create_reply_markup([[("⬅️ Back", "menu_system_adguard")]]),
            )
            return

        # System (Admin-gated)
        if data == "menu_system":
            if not await ensure_admin(update):
                return
            kb = create_reply_markup(
                [
                    [("WOL", "menu_system_wol")],
                    [("Maintenance", "menu_system_this")],
                    [("AdGuard", "menu_system_adguard")],
                    [("⬅️ Back", "menu_main")],
                ]
            )
            await q.edit_message_text("System", reply_markup=kb)
            return

        if data == "menu_system_wol":
            if not await ensure_admin(update):
                return
            rows: List[List[Tuple[str, str]]] = []
            for host in sorted(wake_on_lan_hosts.keys()):
                rows.append([(f"Wake {host}", f"wol__{host}")])
            rows.append([("⬅️ Back", "menu_system")])
            await q.edit_message_text(
                "Wake on LAN", reply_markup=create_reply_markup(rows)
            )
            return

        if data.startswith("wol__"):
            if not await ensure_admin(update):
                return
            host_name = data.split("__", 1)[1]
            host = wake_on_lan_hosts.get(host_name)
            if not host:
                await q.edit_message_text(
                    f"Unknown host '{host_name}'",
                    reply_markup=create_reply_markup([[("⬅️ Back", "menu_system_wol")]]),
                )
                return
            ip_broadcast = host.get("ip") or "255.255.255.255"
            mac = host.get("mac")
            try:
                if not mac:
                    raise ValueError("no MAC address configured")
                await run_blocking(send_magic_packet, mac, ip_address=ip_broadcast)
                msg = f"Sent WOL packet to {host_name}."
            except (ValueError, OSError) as e:
                log.error("WOL to %s FAILED: %s", host_name, e)
                msg = f"Failed to wake {host_name}: {e}"
            await q.edit_message_text(
                msg,
                reply_markup=create_reply_markup([[("⬅️ Back", "menu_system_wol")]]),
            )
            return

        if data == "menu_system_this":
            if not await ensure_admin(update):
                return
            kb = create_reply_markup(
                [[("Reboot", "menu_system_reboot")], [("⬅️ Back", "menu_system")]]
            )
            await q.edit_message_text("Maintenance", reply_markup=kb)
            return

        if data == "menu_system_reboot":
            if not await ensure_admin(update):
                return
            rows = [
                [(f"Reboot {name}", f"reboot__{name}")]
                for name in sorted(router_clients.keys())
            ]
            rows.append([("⬅️ Back", "menu_system_this")])
            await q.edit_message_text("Reboot", reply_markup=create_reply_markup(rows))
            return

        if data.startswith("reboot__"):
            if not await ensure_admin(update):
                return
            name = data.split("__", 1)[1]
            client = router_clients.get(name)
            if not client:
                await q.edit_message_text(
                    f"Unknown router '{name}'",
                    reply_markup=create_reply_markup(
                        [[("⬅️ Back", "menu_system_reboot")]]
                    ),
                )
                return
            try:
                await run_blocking(client.reboot)
                msg = f"Reboot triggered on {name}."
            except OpenWrtError as e:
                msg = f"Failed to reboot {name}: {e}"
            await q.edit_message_text(
                msg,
                reply_markup=create_reply_markup([[("⬅️ Back", "menu_system_reboot")]]),
            )
            return

        # Admin
        if data == "menu_admin":
            if not await ensure_admin(update):
                return
            kb = create_reply_markup(
                [
                    [("Users management", "menu_admin_users")],
                    [("⬅️ Back", "menu_main")],
                ]
            )
            await q.edit_message_text("Admin", reply_markup=kb)
            return

        if data == "menu_admin_users":
            if not await ensure_admin(update):
                return
            kb = create_reply_markup(
                [
                    [("Get User ID", "admin_getuid")],
                    [("Add User", "admin_adduser"), ("Remove User", "admin_userdel")],
                    [("List Users", "admin_listusers")],
                    [("⬅️ Back", "menu_admin")],
                ]
            )
            await q.edit_message_text("Users management", reply_markup=kb)
            return

        if data == "admin_getuid":
            await q.edit_message_text(
                "Users management",
                reply_markup=create_reply_markup(
                    [
                        [("Get User ID ✅", "admin_getuid")],
                        [("⬅️ Back", "menu_admin_users")],
                    ]
                ),
            )
            await q.message.reply_text(f"Your user ID is {uid}")
            return

        if data == "admin_adduser":
            if not await ensure_admin(update):
                return
            context.user_data["awaiting_admin_action"] = "add"
            await q.edit_message_text(
                "Send the numeric Telegram user ID to add (or /cancel).",
                reply_markup=create_reply_markup([[("⬅️ Back", "menu_admin_users")]]),
            )
            return

        if data == "admin_userdel":
            if not await ensure_admin(update):
                return
            context.user_data["awaiting_admin_action"] = "del"
            await q.edit_message_text(
                "Send the numeric Telegram user ID to remove (or /cancel).",
                reply_markup=create_reply_markup([[("⬅️ Back", "menu_admin_users")]]),
            )
            return

        if data == "admin_listusers":
            if not await ensure_admin(update):
                return
            await q.edit_message_text(
                _format_user_list(),
                reply_markup=create_reply_markup([[("⬅️ Back", "menu_admin_users")]]),
            )
            return

        await q.edit_message_text(f"Unknown action: {data}")

    async def on_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
        text = (update.message.text or "").strip()

        # Quick Reply Keyboard buttons
        if text == "🔄 Обновить пульт":
            await cmd_app(update, context)
            return
        if text == "📋 Меню в чате":
            if not await ensure_authorized(update):
                return
            await update.message.reply_text(
                "Быстрое меню в чате:",
                reply_markup=build_inline_menu_markup(update.effective_user.id),
            )
            return

        # Admin intake for add/remove user ID
        action = context.user_data.get("awaiting_admin_action")
        if not action:
            return
        if not await ensure_admin(update):
            context.user_data.pop("awaiting_admin_action", None)
            return

        if not text.isdigit():
            await update.message.reply_text(
                "Please send a numeric user ID (or /cancel)."
            )
            return

        uid = int(text)
        if action == "add":
            access_manager.add_user(uid)
            await update.message.reply_text(f"User {uid} added ✅")
        elif action == "del":
            if access_manager.remove_user(uid):
                await update.message.reply_text(f"User {uid} removed ✅")
            else:
                await update.message.reply_text(
                    f"User {uid} is not in the whitelist."
                )

        context.user_data.pop("awaiting_admin_action", None)

    rpc_bridge_instance: Optional[ServerlessRpcBridge] = None

    async def post_init(application: Application) -> None:
        nonlocal rpc_bridge_instance
        if WEBAPP_LOCAL_SERVER_ENABLED:
            await webapp_server.start()
        else:
            log.info(
                "Running in Serverless Mini App mode (no inbound HTTP port opened on router)."
            )
        if RPC_BRIDGE_ENABLED:
            rpc_bridge_instance = ServerlessRpcBridge(
                bot_token=BOT_TOKEN,
                loop=asyncio.get_running_loop(),
                handle_rpc_Async=handle_rpc_request,
            )
            rpc_bridge_instance.start()
        try:
            # Ensure no global WebApp menu button is exposed to unauthorized users
            await application.bot.set_chat_menu_button(menu_button=MenuButtonDefault())
        except Exception as e:
            log.debug("Could not reset default chat menu button: %s", e)

    async def post_shutdown(application: Application) -> None:
        if rpc_bridge_instance is not None:
            rpc_bridge_instance.stop()
        if WEBAPP_LOCAL_SERVER_ENABLED:
            await webapp_server.stop()

    app = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("app", cmd_app))
    app.add_handler(CommandHandler("get_user_id", cmd_get_user_id))
    app.add_handler(CommandHandler("getuserid", cmd_get_user_id))
    app.add_handler(CommandHandler("adduser", cmd_adduser))
    app.add_handler(CommandHandler("userdel", cmd_userdel))
    app.add_handler(CommandHandler("listusers", cmd_listusers))
    app.add_handler(CommandHandler("cancel", cmd_cancel))
    app.add_handler(CallbackQueryHandler(on_callback))
    app.add_handler(MessageHandler(filters.StatusUpdate.WEB_APP_DATA, on_webapp_data))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text_message))
    return app


async def run_webapp_standalone() -> None:
    await webapp_server.start()
    log.info(
        "Running in standalone Mini App server mode on http://%s:%d",
        WEBAPP_HOST,
        WEBAPP_PORT,
    )
    stop_event = asyncio.Event()
    await stop_event.wait()


def main():
    parser = argparse.ArgumentParser(description="OpenWrt Telegram Bot & Mini App Hub")
    parser.add_argument(
        "--webapp-only",
        action="store_true",
        help="Start only the local Telegram Mini App HTTP server for browser debugging",
    )
    args = parser.parse_args()

    if args.webapp_only:
        asyncio.run(run_webapp_standalone())
        return

    app = build_bot_application()
    log.info("Bot is up.")
    app.run_polling()


if __name__ == "__main__":
    main()
