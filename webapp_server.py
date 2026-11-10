import asyncio
import json
import logging
import mimetypes
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs

from wakeonlan import send_magic_packet

from adguard_client import AdGuardClient, AdGuardError
from auth import AccessManager, AuthUser, verify_telegram_init_data
from openwrt_client import OpenWrtClient, OpenWrtError

log = logging.getLogger("webapp")

WEBAPP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "webapp")


class WebAppServer:
    """
    Lightweight, zero-extra-dependency async HTTP & REST API server for Telegram Mini Apps.
    Designed to run directly on OpenWrt routers in the same Python process as the Telegram bot.
    """

    def __init__(
        self,
        bot_token: str,
        access_manager: AccessManager,
        router_clients: Dict[str, OpenWrtClient],
        adguard_client: Optional[AdGuardClient],
        adguard_default_duration_ms: int,
        wol_hosts: Dict[str, Dict[str, str]],
        executor: ThreadPoolExecutor,
        host: str = "127.0.0.1",
        port: int = 8080,
        dev_mode: bool = False,
        dev_user_id: Optional[int] = None,
    ):
        self.bot_token = bot_token
        self.access = access_manager
        self.router_clients = router_clients
        self.adguard = adguard_client
        self.adguard_default_duration_ms = adguard_default_duration_ms
        self.wol_hosts = wol_hosts or {}
        self.executor = executor
        self.host = host
        self.port = port
        self.dev_mode = dev_mode
        self.dev_user_id = dev_user_id
        self._server: Optional[asyncio.AbstractServer] = None

    async def run_blocking(self, func, *args, **kwargs):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.executor, lambda: func(*args, **kwargs))

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_connection, host=self.host, port=self.port
        )
        log.info(
            "Telegram Mini App HTTP server listening on http://%s:%d (dev_mode=%s)",
            self.host,
            self.port,
            self.dev_mode,
        )

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    # ---------------- HTTP Protocol Handler ----------------
    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not request_line:
                return
            parts = request_line.decode("utf-8", errors="replace").strip().split(" ")
            if len(parts) < 2:
                return
            method, raw_target = parts[0].upper(), parts[1]

            headers: Dict[str, str] = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                if not line or line in (b"\r\n", b"\n"):
                    break
                decoded = line.decode("utf-8", errors="replace").strip()
                if ":" in decoded:
                    k, v = decoded.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            content_length = int(headers.get("content-length", "0") or "0")
            body_bytes = b""
            if 0 < content_length <= 1024 * 256:
                body_bytes = await asyncio.wait_for(
                    reader.readexactly(content_length), timeout=10.0
                )

            parsed_url = urlparse(raw_target)
            path = parsed_url.path
            query = parse_qs(parsed_url.query)

            if method == "OPTIONS":
                await self._send_response(writer, 204, b"", "text/plain")
                return

            status, content, content_type = await self._route_request(
                method, path, query, headers, body_bytes
            )
            await self._send_response(writer, status, content, content_type)
        except Exception as e:
            log.debug("HTTP connection error: %s", e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _send_response(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        body: bytes,
        content_type: str = "application/json; charset=utf-8",
    ) -> None:
        reason = {
            200: "OK",
            204: "No Content",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error",
        }.get(status, "OK")
        header_lines = [
            f"HTTP/1.1 {status} {reason}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            "Access-Control-Allow-Origin: *",
            "Access-Control-Allow-Headers: Content-Type, X-Telegram-Init-Data, Authorization",
            "Access-Control-Allow-Methods: GET, POST, OPTIONS",
            "Cache-Control: no-store",
            "Connection: close",
            "",
            "",
        ]
        writer.write("\r\n".join(header_lines).encode("utf-8") + body)
        await writer.drain()

    def _json_response(self, status: int, payload: Dict[str, Any]) -> Tuple[int, bytes, str]:
        return (
            status,
            json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8",
        )

    # ---------------- Authentication Helper ----------------
    def _authenticate(self, headers: Dict[str, str], query: Dict[str, list]) -> Optional[AuthUser]:
        init_data = headers.get("x-telegram-init-data", "").strip()
        if not init_data:
            auth_hdr = headers.get("authorization", "").strip()
            if auth_hdr.lower().startswith("tma "):
                init_data = auth_hdr[4:].strip()
        if not init_data and "initData" in query:
            init_data = query["initData"][0]

        if init_data:
            tg_user = verify_telegram_init_data(init_data, self.bot_token)
            if not tg_user:
                return None
            uid = int(tg_user["id"])
            role = self.access.get_role(uid)
            return AuthUser(
                user_id=uid,
                first_name=str(tg_user.get("first_name") or ""),
                last_name=str(tg_user.get("last_name") or ""),
                username=str(tg_user.get("username") or ""),
                role=role,
            )

        if self.dev_mode:
            # In dev_mode, allow local testing without Telegram signature
            dev_uid = self.dev_user_id
            if dev_uid is None:
                if self.access.admin_user_ids:
                    dev_uid = sorted(self.access.admin_user_ids)[0]
                elif self.access.whitelisted_users:
                    dev_uid = sorted(self.access.whitelisted_users)[0]
                else:
                    dev_uid = 100000001
            role = self.access.get_role(dev_uid)
            if role == "unauthorized" and not self.access.admin_user_ids:
                role = "admin"
            return AuthUser(
                user_id=dev_uid,
                first_name="Dev",
                last_name="Admin",
                username="dev_mode",
                role=role,
            )

        return None

    # ---------------- Router & Static Serving ----------------
    async def _route_request(
        self,
        method: str,
        path: str,
        query: Dict[str, list],
        headers: Dict[str, str],
        body_bytes: bytes,
    ) -> Tuple[int, bytes, str]:
        # Static & Entry routes for the Logical Mini Apps
        if method == "GET" and path in ("/", "/app", "/home", "/network", "/admin", "/index.html"):
            return self._serve_static_file("index.html")

        if method == "GET" and path in ("/styles.css", "/app.js"):
            return self._serve_static_file(path.lstrip("/"))

        if method == "GET" and path.startswith("/static/"):
            rel_path = path[len("/static/"):]
            return self._serve_static_file(rel_path)

        # Health check endpoint
        if method == "GET" and path == "/api/health":
            return self._json_response(200, {"ok": True})

        # All other /api/* endpoints require Telegram WebApp authentication
        if path.startswith("/api/"):
            user = self._authenticate(headers, query)
            if user is None:
                return self._json_response(
                    401,
                    {
                        "ok": False,
                        "error": "Не удалось проверить подпись Telegram Mini App (initData). Откройте приложение внутри Telegram.",
                    },
                )

            body: Dict[str, Any] = {}
            if body_bytes:
                try:
                    body = json.loads(body_bytes.decode("utf-8"))
                except ValueError:
                    return self._json_response(400, {"ok": False, "error": "Invalid JSON body"})

            return await self._handle_api(method, path, user, body)

        return self._json_response(404, {"ok": False, "error": "Not found"})

    def _serve_static_file(self, filename: str) -> Tuple[int, bytes, str]:
        safe_name = os.path.normpath(filename).lstrip(os.sep)
        full_path = os.path.join(WEBAPP_DIR, safe_name)
        if not os.path.abspath(full_path).startswith(os.path.abspath(WEBAPP_DIR)):
            return self._json_response(403, {"ok": False, "error": "Forbidden"})
        if not os.path.isfile(full_path):
            return self._json_response(404, {"ok": False, "error": f"File {safe_name} not found"})

        ctype, _ = mimetypes.guess_type(full_path)
        if not ctype:
            ctype = "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"

        with open(full_path, "rb") as f:
            data = f.read()
        return 200, data, ctype

    # ---------------- API Business Logic ----------------
    async def _handle_api(
        self, method: str, path: str, user: AuthUser, body: Dict[str, Any]
    ) -> Tuple[int, bytes, str]:
        # 1. /api/me - accessible even to unauthorized users so they can see their Telegram ID
        if method == "GET" and path == "/api/me":
            apps = []
            if user.is_authorized:
                apps.append({
                    "id": "home",
                    "title": "Домашний пульт",
                    "subtitle": "Гостевой Wi-Fi и защита AdGuard",
                    "icon": "home",
                })
            if user.is_admin:
                apps.extend([
                    {
                        "id": "network",
                        "title": "Сеть и Устройства",
                        "subtitle": "Мониторинг роутеров, клиенты, WOL",
                        "icon": "network",
                    },
                    {
                        "id": "admin",
                        "title": "Доступ и Система",
                        "subtitle": "Управление пользователями и ребут",
                        "icon": "shield",
                    },
                ])
            return self._json_response(
                200,
                {
                    "ok": True,
                    "user": user.to_dict(),
                    "apps": apps,
                },
            )

        # Require at least whitelisted user for all following endpoints
        if not user.is_authorized:
            return self._json_response(
                403,
                {
                    "ok": False,
                    "error": f"Нет доступа. Ваш Telegram ID: {user.user_id}",
                    "user": user.to_dict(),
                },
            )

        # 2. Home App endpoints (Guest Wi-Fi + AdGuard) - accessible to 'user' and 'admin'
        if method == "GET" and path == "/api/home":
            wifi_data, adguard_data = await asyncio.gather(
                self._fetch_all_wifi_status(),
                self._fetch_adguard_status(),
            )
            return self._json_response(
                200,
                {
                    "ok": True,
                    "wifi": wifi_data,
                    "adguard": adguard_data,
                },
            )

        if method == "POST" and path == "/api/wifi/toggle":
            action = str(body.get("action") or "").lower()
            target_router = str(body.get("router") or "all")
            if action not in ("on", "off"):
                return self._json_response(400, {"ok": False, "error": "action must be 'on' or 'off'"})

            if target_router != "all":
                if target_router not in self.router_clients:
                    return self._json_response(404, {"ok": False, "error": f"Router '{target_router}' not found"})
                targets = {target_router: self.router_clients[target_router]}
            else:
                targets = self.router_clients

            errors = []

            async def _toggle_one(rname: str, client: OpenWrtClient):
                try:
                    await self.run_blocking(client.toggle_guest_wifi, action)
                except Exception as exc:
                    errors.append(f"{rname}: {exc}")

            await asyncio.gather(*[_toggle_one(n, c) for n, c in targets.items()])
            wifi_data = await self._fetch_all_wifi_status()
            return self._json_response(
                200,
                {
                    "ok": len(errors) == 0,
                    "errors": errors,
                    "wifi": wifi_data,
                },
            )

        if method == "POST" and path == "/api/adguard/toggle":
            if self.adguard is None:
                return self._json_response(400, {"ok": False, "error": "AdGuard is not configured"})

            enabled = bool(body.get("enabled", True))
            duration_minutes = body.get("duration_minutes")
            duration_ms: Optional[int] = None
            if not enabled:
                if duration_minutes is not None:
                    duration_ms = max(1, int(duration_minutes)) * 60 * 1000
                else:
                    duration_ms = self.adguard_default_duration_ms

            try:
                await self.run_blocking(self.adguard.set_protection, enabled, duration_ms)
            except AdGuardError as e:
                return self._json_response(500, {"ok": False, "error": str(e)})

            adguard_data = await self._fetch_adguard_status()
            return self._json_response(200, {"ok": True, "adguard": adguard_data})

        # ---------------- Admin-Only Endpoints ----------------
        if not user.is_admin:
            return self._json_response(
                403,
                {"ok": False, "error": "Это действие доступно только администраторам."},
            )

        # 3. Network & Devices App endpoints (Routers monitoring, Clients, WOL)
        if method == "GET" and path == "/api/network":
            network_data = await self._fetch_network_overview()
            return self._json_response(200, {"ok": True, **network_data})

        if method == "POST" and path == "/api/wol/wake":
            host_name = str(body.get("host") or "").strip()
            host_cfg = self.wol_hosts.get(host_name)
            if not host_cfg:
                return self._json_response(404, {"ok": False, "error": f"Unknown WOL host '{host_name}'"})
            mac = host_cfg.get("mac")
            ip_broadcast = host_cfg.get("ip") or "255.255.255.255"
            if not mac:
                return self._json_response(400, {"ok": False, "error": f"No MAC configured for '{host_name}'"})
            try:
                await self.run_blocking(send_magic_packet, mac, ip_address=ip_broadcast)
                return self._json_response(
                    200,
                    {"ok": True, "message": f"Magic Packet отправлен на {host_name} ({mac})"},
                )
            except Exception as e:
                return self._json_response(500, {"ok": False, "error": f"WOL failed: {e}"})

        if method == "POST" and path == "/api/routers/reboot":
            router_name = str(body.get("router") or "").strip()
            client = self.router_clients.get(router_name)
            if not client:
                return self._json_response(404, {"ok": False, "error": f"Unknown router '{router_name}'"})
            try:
                await self.run_blocking(client.reboot)
                return self._json_response(
                    200,
                    {"ok": True, "message": f"Команда перезагрузки отправлена на {router_name}"},
                )
            except OpenWrtError as e:
                return self._json_response(500, {"ok": False, "error": str(e)})

        # 4. Access & Admin App endpoints (Whitelist management)
        if method == "GET" and path == "/api/admin/users":
            return self._json_response(
                200,
                {
                    "ok": True,
                    "users": self.access.list_users(),
                },
            )

        if method == "POST" and path == "/api/admin/users":
            action = str(body.get("action") or "").lower()
            raw_uid = str(body.get("user_id") or "").strip()
            if not raw_uid.isdigit():
                return self._json_response(400, {"ok": False, "error": "Укажите числовой Telegram User ID"})
            target_uid = int(raw_uid)

            if action == "add":
                self.access.add_user(target_uid)
                return self._json_response(
                    200,
                    {
                        "ok": True,
                        "message": f"Пользователь {target_uid} добавлен в белый список",
                        "users": self.access.list_users(),
                    },
                )
            elif action == "remove":
                if target_uid in self.access.admin_user_ids and target_uid not in self.access.whitelisted_users:
                    return self._json_response(
                        400,
                        {
                            "ok": False,
                            "error": f"Пользователь {target_uid} задан в settings.yaml (admin_user_ids) и не может быть удалён через файл whitelist.",
                        },
                    )
                self.access.remove_user(target_uid)
                return self._json_response(
                    200,
                    {
                        "ok": True,
                        "message": f"Пользователь {target_uid} удалён из белого списка",
                        "users": self.access.list_users(),
                    },
                )
            else:
                return self._json_response(400, {"ok": False, "error": "action must be 'add' or 'remove'"})

        return self._json_response(404, {"ok": False, "error": f"Unknown API endpoint: {method} {path}"})

    # ---------------- Data Aggregators ----------------
    async def _fetch_all_wifi_status(self) -> Dict[str, Any]:
        routers_status: Dict[str, Any] = {}

        async def _check_router(name: str, client: OpenWrtClient):
            try:
                st = await self.run_blocking(client.get_guest_wifi_status)
                routers_status[name] = {"name": name, "ok": True, **st}
            except Exception as e:
                routers_status[name] = {
                    "name": name,
                    "ok": False,
                    "ip": client.cfg.ip,
                    "enabled": False,
                    "all_enabled": False,
                    "ssids": [],
                    "interfaces": [],
                    "error": str(e),
                }

        await asyncio.gather(*[_check_router(n, c) for n, c in self.router_clients.items()])
        ordered = [routers_status[k] for k in sorted(routers_status.keys())]
        any_enabled = any(r.get("enabled") for r in ordered if r.get("ok"))
        all_ssids = []
        for r in ordered:
            for s in r.get("ssids", []):
                if s not in all_ssids:
                    all_ssids.append(s)

        return {
            "enabled": any_enabled,
            "ssids": all_ssids,
            "routers": ordered,
        }

    async def _fetch_adguard_status(self) -> Dict[str, Any]:
        if self.adguard is None:
            return {"configured": False}
        try:
            st = await self.run_blocking(self.adguard.get_status)
            return {"configured": True, "ok": True, **st}
        except Exception as e:
            return {
                "configured": True,
                "ok": False,
                "enabled": False,
                "error": str(e),
            }

    async def _fetch_network_overview(self) -> Dict[str, Any]:
        routers_metrics: Dict[str, Any] = {}
        clients_by_mac: Dict[str, Dict[str, Any]] = {}

        async def _collect_router(name: str, client: OpenWrtClient):
            try:
                metrics, clients = await asyncio.gather(
                    self.run_blocking(client.get_system_metrics),
                    self.run_blocking(client.get_connected_clients),
                )
                routers_metrics[name] = {
                    "name": name,
                    "ok": True,
                    "clients_count": sum(1 for c in clients if c.get("online")),
                    **metrics,
                }
                for c in clients:
                    mac = c["mac"].lower()
                    existing = clients_by_mac.get(mac)
                    if not existing or (c["online"] and not existing["online"]) or (
                        existing["hostname"] in ("Unknown device", "Static IP device")
                        and c["hostname"] not in ("Unknown device", "Static IP device")
                    ):
                        clients_by_mac[mac] = {**c, "router": name}
            except Exception as e:
                routers_metrics[name] = {
                    "name": name,
                    "ok": False,
                    "ip": client.cfg.ip,
                    "error": str(e),
                }

        await asyncio.gather(*[_collect_router(n, c) for n, c in self.router_clients.items()])

        all_clients = sorted(
            clients_by_mac.values(),
            key=lambda c: (not c.get("online", False), c.get("hostname", "").lower(), c.get("ip", "")),
        )

        wol_list = []
        for hname in sorted(self.wol_hosts.keys()):
            hcfg = self.wol_hosts[hname] or {}
            mac = (hcfg.get("mac") or "").strip().lower()
            matched_client = clients_by_mac.get(mac) if mac else None
            wol_list.append({
                "name": hname,
                "mac": mac,
                "broadcast_ip": hcfg.get("ip") or "255.255.255.255",
                "online": bool(matched_client and matched_client.get("online")),
                "detected_ip": matched_client.get("ip") if matched_client else None,
            })

        return {
            "routers": [routers_metrics[k] for k in sorted(routers_metrics.keys())],
            "clients": all_clients,
            "wol_hosts": wol_list,
        }
