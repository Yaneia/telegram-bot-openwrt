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

    # 2. If Admin, also collect router metrics, WOL status, connected clients, and whitelist users
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

        await asyncio.gather(*[_fetch_router_admin(n, c) for n, c in router_clients.items()])

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
        # Keep top 45 clients so the URL fragment stays well under browser/Telegram limits
        snapshot["clients"] = all_clients[:45]
        snapshot["wol_hosts"] = wol_list
        snapshot["admin_users"] = access.list_users()

    return snapshot
