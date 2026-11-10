import json
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class AdGuardError(Exception):
    pass


@dataclass
class AdGuardConfig:
    base_url: str                   # e.g. "https://10.0.0.1/adguard-home"
    username: str
    password: str
    verify_tls: bool = False        # matches curl -k
    timeout: Tuple[int, int] = (5, 10)  # (connect, read)


class AdGuardClient:
    def __init__(self, cfg: AdGuardConfig):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.verify = cfg.verify_tls

        retry = Retry(
            total=3,
            backoff_factor=0.4,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST"]),
        )
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=4)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _url(self, path: str) -> str:
        return self.cfg.base_url.rstrip("/") + "/" + path.lstrip("/")

    def get_status(self) -> Dict[str, Any]:
        """Fetch AdGuard Home protection status and basic DNS statistics."""
        try:
            resp = self.session.get(
                self._url("/control/status"),
                auth=(self.cfg.username, self.cfg.password),
                timeout=self.cfg.timeout,
            )
            resp.raise_for_status()
            status_data = resp.json() if resp.text else {}
        except Exception as e:
            raise AdGuardError(f"AdGuard status check failed: {e}") from e

        stats_summary: Dict[str, Any] = {}
        try:
            stats_resp = self.session.get(
                self._url("/control/stats"),
                auth=(self.cfg.username, self.cfg.password),
                timeout=self.cfg.timeout,
            )
            if stats_resp.ok and stats_resp.text:
                raw_stats = stats_resp.json()
                total_q = int(raw_stats.get("num_dns_queries") or 0)
                blocked_q = int(raw_stats.get("num_blocked_filtering") or 0)
                avg_ms = round(float(raw_stats.get("avg_processing_time") or 0.0) * 1000, 1)
                stats_summary = {
                    "dns_queries": total_q,
                    "blocked_filtering": blocked_q,
                    "blocked_percent": round((blocked_q / total_q) * 100, 1) if total_q > 0 else 0.0,
                    "avg_processing_ms": avg_ms,
                }
        except Exception:
            pass

        return {
            "enabled": bool(status_data.get("protection_enabled", False)),
            "running": bool(status_data.get("running", True)),
            "disabled_duration_ms": int(status_data.get("protection_disabled_duration") or 0),
            "disabled_until": status_data.get("protection_disabled_until"),
            "version": status_data.get("version") or "",
            "stats": stats_summary,
        }

    def set_protection(self, enabled: bool, duration_ms: Optional[int] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"enabled": bool(enabled)}
        if duration_ms is not None:
            payload["duration"] = int(duration_ms)

        try:
            resp = self.session.post(
                self._url("/control/protection"),
                auth=(self.cfg.username, self.cfg.password),
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload),
                timeout=self.cfg.timeout,
            )
            resp.raise_for_status()

            ctype = (resp.headers.get("Content-Type") or "").lower()
            text = (resp.text or "").strip()

            if "application/json" in ctype and text:
                try:
                    return resp.json()
                except ValueError:
                    # Content-Type lied or body is not valid JSON
                    return {"raw": text}

            # If body exists but isn't JSON, return it as raw for debugging
            if text:
                return {"raw": text}

            return {}

        except requests.RequestException as e:
            raise AdGuardError(f"AdGuard request failed: {e}") from e
