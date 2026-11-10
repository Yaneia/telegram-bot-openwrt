import json
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any, Union, List

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3


class OpenWrtError(Exception):
    pass


@dataclass
class RouterConfig:
    ip: str
    username: str = "root"
    password: str = ""
    verify_tls: bool = False  # set to CA file path if you have one, else False
    # Supports a single string, a comma-separated string, or a list of devices
    guest_network_device: Optional[Union[str, List[str]]] = None


class OpenWrtClient:
    """
    Minimal LuCI JSON-RPC client for:
      - auth
      - uci set/commit
      - sys.exec (for wifi reload)
    """
    def __init__(self, cfg: RouterConfig):
        self.cfg = cfg
        self.base = f"https://{cfg.ip}/cgi-bin/luci/rpc"
        self.session = requests.Session()
        self.session.verify = cfg.verify_tls
        if not cfg.verify_tls:
            # Quiet the InsecureRequestWarning spam when TLS verification is off.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # robust retries for transient issues
        retry = Retry(
            total=3,
            backoff_factor=0.4,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["POST"]),
        )
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=4)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        self._token: Optional[str] = None
        self._token_at: float = 0

        # sane default timeout for every HTTP call
        self._timeout = (5, 10)  # (connect, read)

    def _url(self, endpoint: str) -> str:
        return f"{self.base}/{endpoint}"

    def _auth_header(self) -> Dict[str, str]:
        if not self._token or (time.time() - self._token_at) > 50 * 60:
            # (re-)authenticate every 50 minutes just to be safe; LuCI tokens are session cookies
            self.authenticate()
        return {"Cookie": f"sysauth={self._token}"}

    def authenticate(self) -> None:
        payload = {"id": 1, "method": "login", "params": [self.cfg.username, self.cfg.password]}
        try:
            resp = self.session.post(
                self._url("auth"),
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload),
                timeout=self._timeout,
            )
        except requests.RequestException as e:
            raise OpenWrtError(f"Auth network error to {self.cfg.ip}: {e}") from e

        if resp.status_code == 404:
            # luci-mod-rpc is missing or bad URL
            raise OpenWrtError(
                f"LuCI RPC not found at {self._url('auth')}. "
                f"Install luci-mod-rpc and ensure /cgi-bin/luci/rpc/* endpoints are served."
            )

        try:
            resp.raise_for_status()
            body = resp.json()
        except Exception as e:
            raise OpenWrtError(f"Auth http/json error from {self.cfg.ip}: {e}") from e

        token = body.get("result")
        if not token:
            raise OpenWrtError(f"Authentication failed on {self.cfg.ip}. Check credentials.")
        self._token = token
        self._token_at = time.time()

    def _call(self, endpoint: str, method: str, params: list, _retried: bool = False) -> Any:
        """
        Perform a single LuCI JSON-RPC call and return its 'result'.

        Transparently re-authenticates and retries once if the session cookie has
        expired (LuCI answers with HTTP 403), so callers don't fail just because
        the token lapsed sooner than the 50-minute refresh timer.
        """
        payload = {"id": 1, "method": method, "params": params}
        try:
            resp = self.session.post(
                self._url(endpoint),
                headers={"Content-Type": "application/json", **self._auth_header()},
                data=json.dumps(payload),
                timeout=self._timeout,
            )
            if resp.status_code == 403 and not _retried:
                self._token = None  # force re-auth
                return self._call(endpoint, method, params, _retried=True)
            resp.raise_for_status()
            return resp.json().get("result")
        except requests.RequestException as e:
            raise OpenWrtError(f"{endpoint}.{method} error on {self.cfg.ip}: {e}") from e

    def uci_get(self, package: str, section: str, option: Optional[str] = None) -> Any:
        params = [package, section] + ([option] if option else [])
        return self._call("uci", "get", params)

    def uci_get_all(self, package: str, section: Optional[str] = None) -> Any:
        params = [package] + ([section] if section else [])
        return self._call("uci", "get_all", params)

    def uci_set(self, package: str, section: str, option: str, value: str) -> Any:
        return self._call("uci", "set", [package, section, option, value])

    def uci_commit(self, package: str) -> bool:
        # LuCI UCI returns true on success.
        return bool(self._call("uci", "commit", [package]))

    def sys_exec(self, cmd: str) -> str:
        """Run a command via LuCI RPC sys.exec (requires luci-mod-rpc)."""
        # result is usually {"code":0,"stdout":"...","stderr":""}
        res = self._call("sys", "exec", [cmd]) or {}
        if isinstance(res, dict):
            code = res.get("code", 1)
            if code != 0:
                raise OpenWrtError(f"sys.exec non-zero exit {code} on {self.cfg.ip}: {res.get('stderr')}")
            return (res.get("stdout") or "").strip()
        return str(res)

    def get_guest_devices(self) -> List[str]:
        """Return normalized list of configured guest wireless UCI sections."""
        raw_devices = self.cfg.guest_network_device
        if not raw_devices:
            raise OpenWrtError(f"Router {self.cfg.ip} missing guest_network_device in config.")
        if isinstance(raw_devices, str):
            devices = [d.strip() for d in raw_devices.split(",") if d.strip()]
        elif isinstance(raw_devices, list):
            devices = [str(d).strip() for d in raw_devices if d]
        else:
            raise OpenWrtError(f"Invalid guest_network_device format on {self.cfg.ip}")
        if not devices:
            raise OpenWrtError(f"No valid network devices found in config for {self.cfg.ip}")
        return devices

    def get_guest_wifi_status(self) -> Dict[str, Any]:
        """
        Inspect guest Wi-Fi sections via UCI and return status per interface
        plus aggregated router guest Wi-Fi state.
        """
        devices = self.get_guest_devices()
        interfaces: List[Dict[str, Any]] = []
        any_enabled = False
        all_enabled = True
        ssids: List[str] = []

        for section in devices:
            info = {}
            try:
                raw = self.uci_get_all("wireless", section)
                if isinstance(raw, dict):
                    info = raw
            except OpenWrtError:
                pass

            if not info:
                # Fallback to direct uci_get for disabled option
                disabled_raw = self.uci_get("wireless", section, "disabled")
                ssid = None
            else:
                disabled_raw = info.get("disabled")
                ssid = info.get("ssid")

            is_disabled = str(disabled_raw).strip() in ("1", "true", "yes", "on") if disabled_raw is not None else False
            enabled = not is_disabled
            if enabled:
                any_enabled = True
            else:
                all_enabled = False

            if ssid and ssid not in ssids:
                ssids.append(str(ssid))

            interfaces.append({
                "section": section,
                "enabled": enabled,
                "ssid": ssid or section,
                "device": info.get("device") if isinstance(info, dict) else None,
            })

        return {
            "ip": self.cfg.ip,
            "enabled": any_enabled,
            "all_enabled": all_enabled,
            "ssids": ssids,
            "interfaces": interfaces,
        }

    def toggle_guest_wifi(self, action: str) -> bool:
        """
        Toggles one or multiple wireless network devices at once.
        
        action: "on"  -> sets disabled=0
                "off" -> sets disabled=1
                
        This method supports guest_network_device as a single string, 
        a comma-separated string, or a YAML-parsed list of strings.
        It commits all changes and reloads the wifi stack exactly once.
        """
        if action not in ("on", "off"):
            raise ValueError("action must be 'on' or 'off'")

        devices = self.get_guest_devices()
        disabled_value = "0" if action == "on" else "1"

        # 1. Apply the 'disabled' value to every interface in LuCI's staging memory
        for section in devices:
            self.uci_set("wireless", section, "disabled", disabled_value)
        
        # 2. Commit all staged 'wireless' changes to the router's permanent storage
        if not self.uci_commit("wireless"):
            raise OpenWrtError(f"Commit failed on {self.cfg.ip}")

        # 3. Reload the network stack once to apply all changes simultaneously
        # We append '|| true' because /sbin/wifi reload can return exit code 1 
        # even when the configuration is applied successfully.
        try:
            self.sys_exec("/sbin/wifi reload || true")
        except OpenWrtError:
            # Fallback to restarting the network subsystem if the command itself fails to execute
            self.sys_exec("/etc/init.d/network reload || true")

        return True

    def get_system_metrics(self) -> Dict[str, Any]:
        """
        Fetch system metrics (hostname, model, firmware version, uptime, CPU load, RAM usage)
        from OpenWrt using a single lightweight ubus/proc command via sys.exec.
        """
        cmd = (
            "ubus call system board 2>/dev/null || echo '{}'; "
            "echo '---SPLIT---'; "
            "ubus call system info 2>/dev/null || echo '{}'"
        )
        raw = self.sys_exec(cmd)
        parts = raw.split("---SPLIT---")
        board_raw = parts[0].strip() if len(parts) > 0 else "{}"
        info_raw = parts[1].strip() if len(parts) > 1 else "{}"

        try:
            board = json.loads(board_raw) if board_raw else {}
        except ValueError:
            board = {}

        try:
            info = json.loads(info_raw) if info_raw else {}
        except ValueError:
            info = {}

        # Extract memory metrics
        mem = info.get("memory") or {}
        mem_total = int(mem.get("total") or 0)
        mem_avail = int(mem.get("available") or (int(mem.get("free") or 0) + int(mem.get("buffered") or 0) + int(mem.get("cached") or 0)))
        mem_used = max(0, mem_total - mem_avail) if mem_total else 0
        mem_percent = round((mem_used / mem_total) * 100, 1) if mem_total > 0 else 0.0

        # Extract load average (ubus system info returns load scaled by 65536)
        raw_load = info.get("load") or []
        load_avg = [round(int(x) / 65536.0, 2) for x in raw_load[:3]] if raw_load else [0.0, 0.0, 0.0]

        release = board.get("release") or {}
        return {
            "ip": self.cfg.ip,
            "hostname": board.get("hostname") or self.cfg.ip,
            "model": board.get("model") or board.get("board_name") or "OpenWrt Router",
            "version": f"{release.get('distribution', 'OpenWrt')} {release.get('version', '')}".strip(),
            "kernel": board.get("kernel") or "",
            "uptime_seconds": int(info.get("uptime") or 0),
            "load_avg": load_avg,
            "memory": {
                "total_bytes": mem_total,
                "used_bytes": mem_used,
                "available_bytes": mem_avail,
                "percent": mem_percent,
            },
        }

    def get_connected_clients(self) -> List[Dict[str, Any]]:
        """
        Fetch DHCP leases, ARP table, static DHCP host names, and blocked MAC rules
        in a single sys.exec call to return all known LAN & Wi-Fi clients.
        """
        cmd = (
            "cat /tmp/dhcp.leases 2>/dev/null || true; "
            "echo '---ARP---'; "
            "cat /proc/net/arp 2>/dev/null || true; "
            "echo '---UCI_DHCP---'; "
            "uci show dhcp 2>/dev/null | grep -E '\\.(name|mac|ip)=' || true; "
            "echo '---UCI_FW---'; "
            "uci show firewall 2>/dev/null | grep 'tma_block_' || true"
        )
        raw = self.sys_exec(cmd)
        parts = raw.split("---ARP---")
        leases_text = parts[0].strip() if len(parts) > 0 else ""
        rest1 = parts[1] if len(parts) > 1 else ""
        parts2 = rest1.split("---UCI_DHCP---")
        arp_text = parts2[0].strip() if len(parts2) > 0 else ""
        rest2 = parts2[1] if len(parts2) > 1 else ""
        parts3 = rest2.split("---UCI_FW---")
        uci_dhcp_text = parts3[0].strip() if len(parts3) > 0 else ""
        uci_fw_text = parts3[1].strip() if len(parts3) > 1 else ""

        # Parse static DHCP host entries from uci show dhcp
        static_hosts: Dict[str, Dict[str, str]] = {}
        for line in uci_dhcp_text.splitlines():
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip().strip("'\"")
            seg = k.split(".")
            if len(seg) >= 3:
                sec = seg[1]
                field = seg[2]
                static_hosts.setdefault(sec, {})[field] = v

        static_name_by_mac: Dict[str, str] = {}
        static_ip_by_mac: Dict[str, str] = {}
        for sh in static_hosts.values():
            mac_raw = sh.get("mac", "")
            name_raw = sh.get("name", "")
            ip_raw = sh.get("ip", "")
            for m in mac_raw.replace(",", " ").split():
                m_low = m.strip().lower()
                if m_low:
                    if name_raw:
                        static_name_by_mac[m_low] = name_raw
                    if ip_raw:
                        static_ip_by_mac[m_low] = ip_raw

        # Parse blocked MACs from firewall rules named tma_block_<mac_hex>
        blocked_macs = set()
        for line in uci_fw_text.splitlines():
            if "tma_block_" in line:
                idx = line.find("tma_block_")
                hex_part = line[idx + len("tma_block_") : idx + len("tma_block_") + 12].lower()
                if len(hex_part) == 12:
                    mac_str = ":".join(hex_part[i : i + 2] for i in range(0, 12, 2))
                    blocked_macs.add(mac_str)

        # Parse ARP table: IP HWtype Flags HWaddress Mask Device
        arp_by_mac: Dict[str, Dict[str, Any]] = {}
        for line in arp_text.splitlines()[1:]:
            cols = line.split()
            if len(cols) >= 6:
                ip_addr, _hw_type, flags, mac, _mask, dev = cols[:6]
                mac_norm = mac.lower()
                if mac_norm == "00:00:00:00:00:00":
                    continue
                is_reachable = flags.lower() != "0x0"
                arp_by_mac[mac_norm] = {
                    "ip": ip_addr,
                    "mac": mac_norm,
                    "online": is_reachable,
                    "interface": dev,
                }

        clients_by_mac: Dict[str, Dict[str, Any]] = {}
        for line in leases_text.splitlines():
            cols = line.split()
            if len(cols) >= 4:
                expiry, mac, ip_addr, hostname = cols[:4]
                mac_norm = mac.lower()
                arp_entry = arp_by_mac.get(mac_norm, {})
                resolved_name = (
                    hostname
                    if hostname and hostname != "*"
                    else static_name_by_mac.get(mac_norm, mac_norm)
                )
                clients_by_mac[mac_norm] = {
                    "hostname": resolved_name,
                    "ip": ip_addr,
                    "mac": mac_norm,
                    "online": bool(arp_entry.get("online", False)),
                    "interface": arp_entry.get("interface", "lan"),
                    "blocked": mac_norm in blocked_macs,
                    "expires": int(expiry) if expiry.isdigit() else 0,
                }

        # Include ARP entries that might have static IPs (not in dhcp.leases)
        for mac_norm, arp_entry in arp_by_mac.items():
            if mac_norm not in clients_by_mac and arp_entry.get("online"):
                clients_by_mac[mac_norm] = {
                    "hostname": static_name_by_mac.get(mac_norm, arp_entry["ip"]),
                    "ip": arp_entry["ip"],
                    "mac": mac_norm,
                    "online": True,
                    "interface": arp_entry.get("interface", "lan"),
                    "blocked": mac_norm in blocked_macs,
                    "expires": 0,
                }

        # Also include any currently blocked MACs or static hosts not yet in list
        for mac_norm, s_name in static_name_by_mac.items():
            if mac_norm not in clients_by_mac:
                clients_by_mac[mac_norm] = {
                    "hostname": s_name,
                    "ip": static_ip_by_mac.get(mac_norm, "—"),
                    "mac": mac_norm,
                    "online": False,
                    "interface": "lan",
                    "blocked": mac_norm in blocked_macs,
                    "expires": 0,
                }

        result = list(clients_by_mac.values())
        result.sort(key=lambda c: (not c["online"], c["hostname"].lower(), c["ip"]))
        return result

    def kick_wifi_client(self, mac: str) -> bool:
        """Disconnect/deauthenticate a Wi-Fi client across all local OpenWrt hostapd interfaces."""
        clean_mac = mac.strip().lower()
        cmd = (
            "for iface in $(ubus list hostapd.* 2>/dev/null); do "
            f"ubus call $iface del_client '{{\"addr\":\"{clean_mac}\",\"reason\":5,\"deauth\":true,\"ban_time\":3000}}' 2>/dev/null || true; "
            "done"
        )
        self.sys_exec(cmd)
        return True

    def set_client_block(self, mac: str, block: bool, hostname: str = "") -> bool:
        """Block or unblock a client's WAN/forwarding traffic via OpenWrt UCI firewall rule."""
        clean_mac = mac.strip().lower()
        hex_id = clean_mac.replace(":", "").replace("-", "")[:12]
        rule_sec = f"tma_block_{hex_id}"
        if block:
            rule_name = f"Block_{hostname or clean_mac}"
            cmd = (
                f"uci set firewall.{rule_sec}=rule; "
                f"uci set firewall.{rule_sec}.name='{rule_name}'; "
                f"uci set firewall.{rule_sec}.src='lan'; "
                f"uci set firewall.{rule_sec}.dest='wan'; "
                f"uci set firewall.{rule_sec}.src_mac='{clean_mac}'; "
                f"uci set firewall.{rule_sec}.target='REJECT'; "
                f"uci set firewall.{rule_sec}.enabled='1'; "
                "uci commit firewall && /etc/init.d/firewall reload >/dev/null 2>&1 || true"
            )
        else:
            cmd = (
                f"uci -q delete firewall.{rule_sec} || true; "
                "uci commit firewall && /etc/init.d/firewall reload >/dev/null 2>&1 || true"
            )
        self.sys_exec(cmd)
        return True

    def reboot(self) -> None:
        """
        Reboot the router.

        A bare '/sbin/reboot' kills the HTTP connection before the RPC response
        comes back, so sys.exec would report a false failure. We detach and delay
        the reboot slightly so the call returns cleanly first.
        """
        self.sys_exec("(sleep 1; /sbin/reboot) >/dev/null 2>&1 &")

