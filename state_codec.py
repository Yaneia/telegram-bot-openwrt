import asyncio
import base64
import gzip
import hashlib
import hmac
import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional

from adguard_client import AdGuardClient
from auth import AccessManager
from openwrt_client import OpenWrtClient
from unifi_client import UniFiClient


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


def encode_state_token(payload: Dict[str, Any]) -> str:
    """
    Serialize state dict into a compact token for URL hash (#state=...).
    Uses gzip compression ('z.<b64url>') if it shrinks the payload, otherwise plain ('j.<b64url>').
    Because it is placed in the URL fragment (#), browser never sends it to GitHub Pages servers.
    """
    raw_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    compressed = gzip.compress(raw_json, compresslevel=9)
    if len(compressed) < len(raw_json):
        return "z." + _b64url_encode(compressed)
    return "j." + _b64url_encode(raw_json)


def decode_state_token(token: str) -> Dict[str, Any]:
    """Decode a 'z.<b64url>' or 'j.<b64url>' state token (used for testing & verification)."""
    if token.startswith("z."):
        raw = gzip.decompress(_b64url_decode(token[2:]))
        return json.loads(raw.decode("utf-8"))
    if token.startswith("j."):
        raw = _b64url_decode(token[2:])
        return json.loads(raw.decode("utf-8"))
    raise ValueError("Unsupported state token prefix")


def sign_action_token(action_payload: Dict[str, Any], bot_token: str) -> str:
    """Create a short HMAC-signed token for /start deep-link fallback."""
    data = dict(action_payload)
    data["ts"] = int(time.time())
    raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    b64 = _b64url_encode(raw)
    sig = hmac.new(bot_token.encode("utf-8"), b64.encode("ascii"), hashlib.sha256).hexdigest()[:16]
    return f"{b64}.{sig}"


def verify_action_token(token: str, bot_token: str, max_age_sec: int = 3600) -> Optional[Dict[str, Any]]:
    """Verify HMAC-signed action token from /start deep-link."""
    if "." not in token:
        return None
    b64, sig = token.rsplit(".", 1)
    expected = hmac.new(bot_token.encode("utf-8"), b64.encode("ascii"), hashlib.sha256).hexdigest()[:16]
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        data = json.loads(_b64url_decode(b64).decode("utf-8"))
        ts = int(data.get("ts") or 0)
        if max_age_sec > 0 and abs(time.time() - ts) > max_age_sec:
            return None
        return data
    except Exception:
        return None


async def build_serverless_snapshot(
    user_id: int,
    first_name: str,
    username: str,
    access: AccessManager,
    router_clients: Dict[str, OpenWrtClient],
    adguard: Optional[AdGuardClient],
    wol_hosts: Dict[str, Dict[str, str]],
    executor: ThreadPoolExecutor,
    bot_username: str = "",
    unifi: Optional[UniFiClient] = None,
) -> Dict[str, Any]:
    """
    Collect live status from OpenWrt routers and AdGuard Home locally on the router
    to embed into the serverless Mini App URL hash (#state=...).
    Strictly filters included data by the user's role ('user' vs 'admin').
    """
    loop = asyncio.get_running_loop()

    async def run_blocking(func, *args):
        return await loop.run_in_executor(executor, lambda: func(*args))

    role = access.get_role(user_id)
    is_admin = role == "admin"
    is_authorized = role in ("admin", "user")

    snapshot: Dict[str, Any] = {
        "serverless": True,
        "ts": int(time.time()),
        "bot_username": bot_username,
        "user": {
            "user_id": user_id,
            "first_name": first_name,
            "last_name": "",
            "username": username,
            "role": role,
            "is_authorized": is_authorized,
            "is_admin": is_admin,
        },
    }

    if not is_authorized:
        return snapshot

    # 1. Fetch Guest Wi-Fi & AdGuard status (for both 'user' and 'admin')
    routers_wifi: Dict[str, Any] = {}

    async def _fetch_wifi(rname: str, client: OpenWrtClient):
        try:
            st = await run_blocking(client.get_guest_wifi_status)
            routers_wifi[rname] = {"name": rname, "ok": True, **st}
        except Exception as e:
            routers_wifi[rname] = {
                "name": rname,
                "ok": False,
                "ip": client.cfg.ip,
                "enabled": False,
                "ssids": [],
                "interfaces": [],
                "error": str(e),
            }

    async def _fetch_ag():
        if adguard is None:
            return {"configured": False}
        try:
            st = await run_blocking(adguard.get_status)
            return {"configured": True, "ok": True, **st}
        except Exception as e:
            return {"configured": True, "ok": False, "enabled": False, "error": str(e)}

    tasks = [_fetch_wifi(n, c) for n, c in router_clients.items()]
    ag_task = asyncio.create_task(_fetch_ag())
    await asyncio.gather(*tasks)
    adguard_data = await ag_task

    ordered_wifi = [routers_wifi[k] for k in sorted(routers_wifi.keys())]
    any_wifi_on = any(r.get("enabled") for r in ordered_wifi if r.get("ok"))
    ssids = []
    for r in ordered_wifi:
        for s in r.get("ssids", []):
            if s not in ssids:
                ssids.append(s)

    snapshot["wifi"] = {
        "enabled": any_wifi_on,
        "ssids": ssids,
        "routers": ordered_wifi,
    }
    snapshot["adguard"] = adguard_data

    # 1b. If UniFi is configured and user is not admin, fetch only guest WLANs for Home screen
    if unifi is not None and not is_admin:
        try:
            all_wlans = await run_blocking(unifi.get_wlans)
            guest_wlans = [w for w in all_wlans if w.get("is_guest")]
            snapshot["unifi"] = {"configured": True, "ok": True, "wlans": guest_wlans}
        except Exception as e:
            snapshot["unifi"] = {"configured": True, "ok": False, "error": str(e), "wlans": []}

    # 2. If Admin, also collect router metrics, WOL status, connected clients, UniFi overview, and whitelist users
    if is_admin:
        routers_metrics: Dict[str, Any] = {}
        clients_by_mac: Dict[str, Dict[str, Any]] = {}

        async def _fetch_router_admin(rname: str, client: OpenWrtClient):
            try:
                metrics, clients = await asyncio.gather(
                    run_blocking(client.get_system_metrics),
                    run_blocking(client.get_connected_clients),
                )
                routers_metrics[rname] = {
                    "name": rname,
                    "ok": True,
                    "clients_count": sum(1 for c in clients if c.get("online")),
                    **metrics,
                }
                for c in clients:
                    mac = c["mac"].lower()
                    existing = clients_by_mac.get(mac)
                    if not existing or (c["online"] and not existing["online"]):
                        clients_by_mac[mac] = {
                            "hostname": c["hostname"],
                            "ip": c["ip"],
                            "mac": mac,
                            "online": c["online"],
                            "router": rname,
                        }
            except Exception as e:
                routers_metrics[rname] = {
                    "name": rname,
                    "ok": False,
                    "ip": client.cfg.ip,
                    "error": str(e),
                }

        async def _fetch_unifi_admin():
            if unifi is None:
                return {"configured": False}
            try:
                ov = await run_blocking(unifi.get_overview)
                return {"configured": True, "ok": True, **(ov or {})}
            except Exception as e:
                return {"configured": True, "ok": False, "error": str(e)}

        unifi_task = asyncio.create_task(_fetch_unifi_admin())
        await asyncio.gather(*[_fetch_router_admin(n, c) for n, c in router_clients.items()])
        snapshot["unifi"] = await unifi_task

        all_clients = sorted(
            clients_by_mac.values(),
            key=lambda c: (not c.get("online", False), c.get("hostname", "").lower()),
        )

        wol_list = []
        for hname in sorted((wol_hosts or {}).keys()):
            hcfg = wol_hosts[hname] or {}
            mac = (hcfg.get("mac") or "").strip().lower()
            matched = clients_by_mac.get(mac) if mac else None
            wol_list.append({
                "name": hname,
                "mac": mac,
                "online": bool(matched and matched.get("online")),
                "detected_ip": matched.get("ip") if matched else None,
            })

        snapshot["routers"] = [routers_metrics[k] for k in sorted(routers_metrics.keys())]
        # Keep top 30 clients so the URL fragment stays compact
        snapshot["clients"] = all_clients[:30]
        snapshot["wol_hosts"] = wol_list
        snapshot["admin_users"] = access.list_users()

    return snapshot


def _encode_network_with_budget(network_snap: Dict[str, Any], max_len: int = 750) -> str:
    """Encode the network tab snapshot, trimming the clients list if needed to stay under max_len chars."""
    clients = list(network_snap.get("clients") or [])
    token = encode_state_token(network_snap)
    while len(token) > max_len and clients:
        # Trim clients list by ~25% each step
        new_count = max(0, int(len(clients) * 0.7) - 1)
        clients = clients[:new_count]
        network_snap["clients"] = clients
        token = encode_state_token(network_snap)
    return token


def _encode_unifi_with_budget(unifi_snap: Dict[str, Any], max_len: int = 750) -> str:
    """Encode the UniFi tab snapshot, trimming clients/poe details if needed to stay under max_len chars."""
    unifi_data = dict(unifi_snap.get("unifi") or {})
    unifi_snap["unifi"] = unifi_data
    clients = list(unifi_data.get("clients") or [])
    token = encode_state_token(unifi_snap)
    while len(token) > max_len and clients:
        new_count = max(0, int(len(clients) * 0.7) - 1)
        clients = clients[:new_count]
        unifi_data["clients"] = clients
        token = encode_state_token(unifi_snap)
    if len(token) > max_len and unifi_data.get("devices"):
        # Strip poe_ports detail if still over budget
        slim_devs = []
        for d in unifi_data["devices"]:
            dc = dict(d)
            dc["poe_ports"] = []
            slim_devs.append(dc)
        unifi_data["devices"] = slim_devs
        token = encode_state_token(unifi_snap)
    return token


def split_snapshot_into_app_tokens(
    snapshot: Dict[str, Any],
    max_per_button_len: int = 750,
) -> Dict[str, str]:
    """
    Split a full serverless snapshot into compact per-app tokens ('home', 'network', 'unifi', 'admin')
    so that all 4 buttons together in Telegram's ReplyKeyboardMarkup stay strictly under 4 KB.
    """
    base = {
        "serverless": True,
        "ts": snapshot.get("ts", int(time.time())),
        "bot_username": snapshot.get("bot_username", ""),
        "user": snapshot.get("user", {}),
    }

    # 1. Home token (OpenWrt Guest Wi-Fi + AdGuard + UniFi Guest WLANs)
    home_snap: Dict[str, Any] = {
        **base,
        "scope": "home",
        "wifi": snapshot.get("wifi"),
        "adguard": snapshot.get("adguard"),
    }
    unifi_raw = snapshot.get("unifi")
    if isinstance(unifi_raw, dict) and unifi_raw.get("configured"):
        guest_wlans = [w for w in (unifi_raw.get("wlans") or []) if w.get("is_guest")]
        if guest_wlans:
            home_snap["unifi"] = {"configured": True, "ok": True, "wlans": guest_wlans}

    tokens: Dict[str, str] = {
        "home": encode_state_token(home_snap),
    }

    is_admin = bool(snapshot.get("user", {}).get("is_admin"))
    if is_admin:
        # 2. Network & WOL token
        network_snap: Dict[str, Any] = {
            **base,
            "scope": "network",
            "routers": snapshot.get("routers") or [],
            "wol_hosts": snapshot.get("wol_hosts") or [],
            "clients": list(snapshot.get("clients") or []),
        }
        tokens["network"] = _encode_network_with_budget(network_snap, max_len=max_per_button_len)

        # 3. UniFi token
        if isinstance(unifi_raw, dict) and unifi_raw.get("configured"):
            unifi_snap: Dict[str, Any] = {
                **base,
                "scope": "unifi",
                "unifi": dict(unifi_raw),
            }
            tokens["unifi"] = _encode_unifi_with_budget(unifi_snap, max_len=max_per_button_len)

        # 4. Admin / Whitelist Users token
        admin_snap: Dict[str, Any] = {
            **base,
            "scope": "admin",
            "admin_users": snapshot.get("admin_users") or [],
        }
        tokens["admin"] = encode_state_token(admin_snap)

    return tokens
