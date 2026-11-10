import json
import logging
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any, List, Tuple

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("unifi")


class UniFiError(Exception):
    pass


@dataclass
class UniFiConfig:
    base_url: str = "https://127.0.0.1:11443"
    username: str = ""
    password: str = ""
    api_key: str = ""               # Optional: UniFi OS Integration API Key (X-API-KEY)
    site: str = "default"
    verify_tls: bool = False
    is_unifi_os: Optional[bool] = None  # None = auto-detect (/proxy/network vs classic)
    guest_wlan_names: Optional[List[str]] = None  # Optional list of guest WLAN SSIDs users can toggle
    timeout: Tuple[int, int] = (5, 10)


class UniFiClient:
    """
    Lightweight client for UniFi OS Server (e.g. port 11443/443) and Classic UniFi Network Controller (8443).
    Supports:
      - WLAN (SSID) listing & enable/disable toggles
      - AP & Switch monitoring (CPU, RAM, Uptime, clients, PoE ports)
      - AP Reboot, LED override toggle (on/off/default), PoE port power-cycle
      - Active Wi-Fi/Wired clients with signal (dBm), AP name, SSID, Kick (reconnect) & Block/Unblock
    """

    def __init__(self, cfg: UniFiConfig):
        self.cfg = cfg
        self.base_url = cfg.base_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = cfg.verify_tls
        if not cfg.verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        retry = Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=(429, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST", "PUT"]),
        )
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=4)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        self._is_unifi_os: Optional[bool] = cfg.is_unifi_os
        self._csrf_token: Optional[str] = None
        self._logged_in_at: float = 0.0
        self._site_verified: bool = False

    def _headers(self) -> Dict[str, str]:
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.cfg.api_key:
            hdrs["X-API-KEY"] = self.cfg.api_key
        if self._csrf_token:
            hdrs["X-CSRF-Token"] = self._csrf_token
        return hdrs

    def authenticate(self) -> None:
        if self.cfg.api_key:
            # When using an API key, detect whether /proxy/network prefix is used
            if self._is_unifi_os is None:
                self._is_unifi_os = True
            self._logged_in_at = time.time()
            return

        if not self.cfg.username or not self.cfg.password:
            raise UniFiError("UniFi credentials missing (set username/password or api_key in settings.yaml)")

        # Try UniFi OS login (/api/auth/login) first unless explicitly set to False
        endpoints = []
        if self._is_unifi_os is True:
            endpoints = [("/api/auth/login", True)]
        elif self._is_unifi_os is False:
            endpoints = [("/api/login", False)]
        else:
            endpoints = [("/api/auth/login", True), ("/api/login", False)]

        last_err = None
        for path, is_uos in endpoints:
            url = f"{self.base_url}{path}"
            payload = {
                "username": self.cfg.username,
                "password": self.cfg.password,
                "rememberMe": True,
            }
            try:
                resp = self.session.post(
                    url,
                    headers={"Content-Type": "application/json"},
                    data=json.dumps(payload),
                    timeout=self.cfg.timeout,
                )
                if resp.status_code in (200, 204):
                    self._is_unifi_os = is_uos
                    csrf = resp.headers.get("X-CSRF-Token") or resp.headers.get("x-csrf-token")
                    if csrf:
                        self._csrf_token = csrf
                    self._logged_in_at = time.time()
                    return
                last_err = f"HTTP {resp.status_code} on {path}"
            except requests.RequestException as e:
                last_err = str(e)

        raise UniFiError(f"UniFi login failed ({self.base_url}): {last_err}")

    def _site_url(self, subpath: str) -> str:
        prefix = "/proxy/network" if self._is_unifi_os is not False else ""
        clean = subpath.lstrip("/")
        return f"{self.base_url}{prefix}/api/s/{self.cfg.site}/{clean}"

    def _request(
        self,
        method: str,
        subpath: str,
        payload: Optional[Dict[str, Any]] = None,
        _retried: bool = False,
    ) -> Any:
        if not self.cfg.api_key and (
            not self._logged_in_at or (time.time() - self._logged_in_at) > 45 * 60
        ):
            self.authenticate()

        url = self._site_url(subpath)
        try:
            resp = self.session.request(
                method=method.upper(),
                url=url,
                headers=self._headers(),
                data=json.dumps(payload) if payload is not None else None,
                timeout=self.cfg.timeout,
            )
            csrf = (
                resp.headers.get("X-Updated-CSRF-Token")
                or resp.headers.get("X-CSRF-Token")
                or resp.headers.get("x-csrf-token")
            )
            if csrf:
                self._csrf_token = csrf

            if resp.status_code in (401, 403) and not _retried and not self.cfg.api_key:
                self._logged_in_at = 0.0
                self.authenticate()
                return self._request(method, subpath, payload, _retried=True)

            resp.raise_for_status()
            if not resp.text:
                return {}
            body = resp.json()
            if isinstance(body, dict) and "data" in body:
                return body["data"]
            return body
        except requests.RequestException as e:
            raise UniFiError(f"UniFi API {method} {subpath} error: {e}") from e

    # ---------------- High-Level Queries ----------------
    def get_wlans(self) -> List[Dict[str, Any]]:
        raw = self._request("GET", "rest/wlanconf") or []
        wlans = []
        guest_names = [g.lower() for g in (self.cfg.guest_wlan_names or [])]
        for w in raw:
            if not isinstance(w, dict):
                continue
            name = str(w.get("name") or "SSID")
            is_guest = bool(w.get("is_guest")) or (name.lower() in guest_names)
            wlans.append({
                "id": str(w.get("_id") or ""),
                "name": name,
                "enabled": bool(w.get("enabled", True)),
                "is_guest": is_guest,
                "band": str(w.get("wlan_band") or "both"),
                "security": str(w.get("security") or "wpapsk"),
            })
        wlans.sort(key=lambda x: (not x["is_guest"], x["name"].lower()))
        return wlans

    def _raw_url(self, path: str) -> str:
        prefix = "/proxy/network" if self._is_unifi_os is not False else ""
        clean = path.lstrip("/")
        return f"{self.base_url}{prefix}/{clean}"

    def _ensure_site_resolved(self) -> None:
        if self._site_verified:
            return
        self._site_verified = True
        try:
            resp = self.session.get(
                self._raw_url("api/self/sites"),
                headers=self._headers(),
                timeout=self.cfg.timeout,
            )
            if resp.status_code == 200 and resp.text:
                body = resp.json()
                sites = body.get("data") if isinstance(body, dict) else body
                if isinstance(sites, list) and sites:
                    names = [str(s.get("name") or "") for s in sites if isinstance(s, dict)]
                    if self.cfg.site not in names:
                        # Check if user passed site 'desc' instead of internal 'name', or fall back to first site
                        matched = next(
                            (
                                str(s.get("name"))
                                for s in sites
                                if isinstance(s, dict)
                                and str(s.get("desc") or "").lower() == self.cfg.site.lower()
                            ),
                            names[0] if names else self.cfg.site,
                        )
                        if matched:
                            log.info("UniFi resolved site '%s' -> '%s'", self.cfg.site, matched)
                            self.cfg.site = matched
        except Exception as e:
            log.debug("UniFi site auto-resolve skipped: %s", e)

    def get_overview(self) -> Dict[str, Any]:
        """
        Fetch UniFi WLANs, Devices (APs & Switches), and Active Clients.
        """
        if not self.cfg.api_key and not self._logged_in_at:
            self.authenticate()
        self._ensure_site_resolved()

        wlans = self.get_wlans()
        raw_devices = self._request("GET", "stat/device") or []
        raw_clients = self._request("GET", "stat/sta") or []

        # Fallback: On newer UniFi OS / Network 8.x+, if stat/sta is empty, try v2 active clients endpoint
        if not raw_clients:
            try:
                v2_resp = self.session.get(
                    self._raw_url(f"v2/api/site/{self.cfg.site}/clients/active"),
                    headers=self._headers(),
                    timeout=self.cfg.timeout,
                )
                if v2_resp.status_code == 200 and v2_resp.text:
                    v2_body = v2_resp.json()
                    if isinstance(v2_body, list):
                        raw_clients = v2_body
                    elif isinstance(v2_body, dict) and isinstance(v2_body.get("data"), list):
                        raw_clients = v2_body["data"]
            except Exception as e:
                log.debug("UniFi v2 clients fallback error: %s", e)

        ap_names_by_mac: Dict[str, str] = {}
        devices: List[Dict[str, Any]] = []

        for d in raw_devices:
            if not isinstance(d, dict):
                continue
            mac = str(d.get("mac") or "").lower()
            name = str(d.get("name") or d.get("model") or mac)
            if mac:
                ap_names_by_mac[mac] = name

            sys_stats = d.get("system-stats") or {}
            cpu_val = round(float(sys_stats.get("cpu") or 0.0), 1)
            mem_val = round(float(sys_stats.get("mem") or 0.0), 1)

            # Extract PoE ports if this device is a PoE switch
            poe_ports = []
            for p in d.get("port_table") or []:
                if isinstance(p, dict) and p.get("poe_enable"):
                    poe_ports.append({
                        "port_idx": int(p.get("port_idx") or 0),
                        "name": str(p.get("name") or f"Port {p.get('port_idx')}"),
                        "up": bool(p.get("up", False)),
                        "poe_power_w": round(float(p.get("poe_power") or 0.0), 1),
                    })

            devices.append({
                "id": str(d.get("_id") or ""),
                "mac": mac,
                "name": name,
                "model": str(d.get("model") or "UniFi Device"),
                "type": str(d.get("type") or "uap"),
                "ip": str(d.get("ip") or ""),
                "version": str(d.get("version") or ""),
                "online": int(d.get("state") or 0) == 1,
                "uptime_seconds": int(d.get("uptime") or 0),
                "cpu_percent": cpu_val,
                "mem_percent": mem_val,
                "num_sta": int(d.get("num_sta") or 0),
                "led_override": str(d.get("led_override") or "default"),
                "poe_ports": poe_ports[:16],
            })

        devices.sort(key=lambda x: (not x["online"], x["name"].lower()))

        clients: List[Dict[str, Any]] = []
        for c in raw_clients:
            if not isinstance(c, dict):
                continue
            mac = str(c.get("mac") or "").lower()
            hostname = str(
                c.get("name")
                or c.get("display_name")
                or c.get("hostname")
                or c.get("oui")
                or mac
            )
            ap_mac = str(c.get("ap_mac") or c.get("uplink_mac") or "").lower()
            signal = c.get("signal") if c.get("signal") is not None else c.get("rssi")
            is_wired = bool(c.get("is_wired", False)) or str(c.get("type") or "").upper() == "WIRED"
            ip_val = str(c.get("ip") or c.get("last_ip") or "—")
            essid_val = str(c.get("essid") or c.get("ssid") or ("LAN" if is_wired else ""))
            ap_name_val = str(c.get("uplink_name") or ap_names_by_mac.get(ap_mac, ap_mac or "Switch"))
            clients.append({
                "mac": mac,
                "hostname": hostname,
                "ip": ip_val,
                "essid": essid_val,
                "ap_name": ap_name_val,
                "is_wired": is_wired,
                "is_guest": bool(c.get("is_guest", False)),
                "signal_dbm": int(signal) if signal is not None else None,
                "radio": str(c.get("radio_proto") or c.get("radio") or ""),
            })

        clients.sort(key=lambda x: (x["is_wired"], x["hostname"].lower()))
        log.info(
            "UniFi [%s] overview: %d WLANs, %d devices, %d clients",
            self.cfg.site,
            len(wlans),
            len(devices),
            len(clients),
        )

        return {
            "configured": True,
            "ok": True,
            "wlans": wlans,
            "devices": devices,
            "clients": clients[:45],
        }

    # ---------------- Actions & Mutations ----------------
    def toggle_wlan(self, wlan_id: str, enabled: bool) -> bool:
        if not wlan_id:
            raise UniFiError("Missing wlan_id")
        self._request("PUT", f"rest/wlanconf/{wlan_id}", {"enabled": bool(enabled)})
        return True

    def restart_device(self, device_mac: str) -> bool:
        if not device_mac:
            raise UniFiError("Missing device MAC")
        self._request("POST", "cmd/devmgr", {"cmd": "restart", "mac": device_mac.lower()})
        return True

    def set_device_led(self, device_id: str, mode: str) -> bool:
        if mode not in ("on", "off", "default"):
            raise ValueError("LED mode must be 'on', 'off', or 'default'")
        self._request("PUT", f"rest/device/{device_id}", {"led_override": mode})
        return True

    def power_cycle_poe_port(self, switch_mac: str, port_idx: int) -> bool:
        self._request(
            "POST",
            "cmd/devmgr",
            {"cmd": "power-cycle", "mac": switch_mac.lower(), "port_idx": int(port_idx)},
        )
        return True

    def kick_client(self, client_mac: str) -> bool:
        self._request("POST", "cmd/stamgr", {"cmd": "kick-sta", "mac": client_mac.lower()})
        return True

    def set_client_block(self, client_mac: str, block: bool) -> bool:
        cmd = "block-sta" if block else "unblock-sta"
        self._request("POST", "cmd/stamgr", {"cmd": cmd, "mac": client_mac.lower()})
        return True
