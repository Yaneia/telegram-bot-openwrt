import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import threading
import time
from typing import Dict, Any, Callable, Awaitable, Optional

import requests

from state_codec import encode_state_token

log = logging.getLogger("rpc_bridge")

DEFAULT_RELAY_BASE = "https://ntfy.sh"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


def derive_rpc_credentials(bot_token: str) -> Dict[str, str]:
    """
    Derive a deterministic private request topic and encryption key from BOT_TOKEN.
    Passed inside the encrypted #state snapshot to authorized Mini App users.
    """
    req_topic = (
        "owrt_q_"
        + hmac.new(bot_token.encode("utf-8"), b"tma-rpc-topic-v1", hashlib.sha256).hexdigest()[:16]
    )
    rpc_key = hmac.new(
        bot_token.encode("utf-8"), b"tma-rpc-key-v1", hashlib.sha256
    ).hexdigest()[:20]
    return {
        "topic": req_topic,
        "key": rpc_key,
    }


def _xor_keystream(data: bytes, key_str: str, nonce_str: str) -> bytes:
    out = bytearray(len(data))
    block_count = (len(data) + 31) // 32
    for i in range(block_count):
        seed = f"{key_str}:{nonce_str}:{i}".encode("ascii")
        ks = hashlib.sha256(seed).digest()
        start = i * 32
        end = min(start + 32, len(data))
        for j in range(start, end):
            out[j] = data[j] ^ ks[j - start]
    return bytes(out)


def encrypt_rpc_packet(inner_text: str, key_str: str) -> str:
    """
    Encrypt a string (such as a 'z.<gzip>' token or JSON string) into 'e1.<nonce>.<mac>.<b64url>'.
    Uses SHA-256 stream cipher + SHA-256 MAC so both Python stdlib and browser WebCrypto work natively.
    """
    nonce_str = os.urandom(8).hex()
    plain_bytes = inner_text.encode("utf-8")
    cipher_bytes = _xor_keystream(plain_bytes, key_str, nonce_str)
    mac_prefix = f"{key_str}:{nonce_str}:mac:".encode("ascii")
    mac_hex = hashlib.sha256(mac_prefix + cipher_bytes).hexdigest()[:24]
    return f"e1.{nonce_str}.{mac_hex}.{_b64url_encode(cipher_bytes)}"


def decrypt_rpc_packet(packet: str, key_str: str) -> Optional[str]:
    """
    Verify MAC and decrypt an 'e1.<nonce>.<mac>.<b64url>' packet.
    Returns the decrypted inner UTF-8 string, or None if invalid.
    """
    try:
        parts = packet.strip().split(".")
        if len(parts) != 4 or parts[0] != "e1":
            return None
        _, nonce_str, mac_hex, b64_cipher = parts
        cipher_bytes = _b64url_decode(b64_cipher)
        mac_prefix = f"{key_str}:{nonce_str}:mac:".encode("ascii")
        expected_mac = hashlib.sha256(mac_prefix + cipher_bytes).hexdigest()[:24]
        if not hmac.compare_digest(mac_hex, expected_mac):
            return None
        plain_bytes = _xor_keystream(cipher_bytes, key_str, nonce_str)
        return plain_bytes.decode("utf-8")
    except Exception:
        return None


class ServerlessRpcBridge:
    """
    Zero-port outbound HTTPS RPC bridge for the Telegram Mini App.
    Listens on an outbound HTTPS stream (ntfy.sh) and executes Mini App commands in real time
    so the Mini App never closes and never spams the Telegram chat.
    """

    def __init__(
        self,
        bot_token: str,
        loop: asyncio.AbstractEventLoop,
        handle_rpc_Async: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]],
    ):
        self.creds = derive_rpc_credentials(bot_token)
        self.relay_base = self.creds.get("relay", DEFAULT_RELAY_BASE).rstrip("/")
        self.req_topic = self.creds["topic"]
        self.rpc_key = self.creds["key"]
        self.loop = loop
        self.handle_rpc_async = handle_rpc_Async
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._seen_req_ids = set()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._listen_loop, name="tma-rpc-bridge", daemon=True
        )
        self._thread.start()
        log.info("Serverless RPC Bridge active (zero inbound ports, background Mini App sync enabled).")

    def stop(self) -> None:
        self._stop_event.set()

    def _listen_loop(self) -> None:
        session = requests.Session()
        stream_url = f"{self.relay_base}/{self.req_topic}/json"
        while not self._stop_event.is_set():
            try:
                with session.get(stream_url, stream=True, timeout=(10, 75)) as resp:
                    if resp.status_code != 200:
                        time.sleep(3)
                        continue
                    for raw_line in resp.iter_lines(decode_unicode=True):
                        if self._stop_event.is_set():
                            break
                        if not raw_line:
                            continue
                        try:
                            ev = json.loads(raw_line)
                        except ValueError:
                            continue
                        if ev.get("event") != "message":
                            continue
                        msg_text = ev.get("message") or ""
                        if not msg_text.startswith("e1."):
                            continue
                        decrypted = decrypt_rpc_packet(msg_text, self.rpc_key)
                        if not decrypted:
                            continue
                        try:
                            req_data = json.loads(decrypted)
                        except ValueError:
                            continue
                        req_id = str(req_data.get("req_id") or "")
                        if not req_id or req_id in self._seen_req_ids:
                            continue
                        # Reject stale requests older than 120s
                        req_ts = int(req_data.get("ts") or 0)
                        if req_ts and abs(time.time() - req_ts) > 120:
                            continue
                        self._seen_req_ids.add(req_id)
                        if len(self._seen_req_ids) > 500:
                            self._seen_req_ids.clear()

                        asyncio.run_coroutine_threadsafe(
                            self._process_and_reply(req_id, req_data),
                            self.loop,
                        )
            except Exception as e:
                if not self._stop_event.is_set():
                    log.debug("RPC stream reconnect: %s", e)
                    time.sleep(2)

    async def _process_and_reply(self, req_id: str, req_data: Dict[str, Any]) -> None:
        try:
            response_dict = await self.handle_rpc_async(req_data)
        except Exception as e:
            log.warning("RPC handler error: %s", e)
            response_dict = {"ok": False, "error": str(e)}

        try:
            # Compress response dict into a 'z.<b64url>' token (cap around 3200 chars so it stays < 4KB on relay)
            compressed_token = encode_state_token(response_dict)
            if len(compressed_token) > 3400 and "snapshot" in response_dict:
                snap = response_dict["snapshot"]
                if isinstance(snap, dict):
                    if "clients" in snap and isinstance(snap["clients"], list):
                        snap["clients"] = snap["clients"][:25]
                    if "unifi" in snap and isinstance(snap["unifi"], dict):
                        u_clients = snap["unifi"].get("clients")
                        if isinstance(u_clients, list):
                            snap["unifi"]["clients"] = u_clients[:25]
                    compressed_token = encode_state_token(response_dict)

            encrypted_reply = encrypt_rpc_packet(compressed_token, self.rpc_key)
            res_topic = f"owrt_r_{req_id}"
            res_url = f"{self.relay_base}/{res_topic}"
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                lambda: requests.post(
                    res_url,
                    data=encrypted_reply.encode("utf-8"),
                    headers={"Title": "rpc", "Cache": "yes"},
                    timeout=(5, 10),
                ),
            )
        except Exception as e:
            log.warning("Failed to publish RPC reply for %s: %s", req_id, e)
