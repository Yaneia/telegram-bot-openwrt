# OpenWRT Control Bot & Serverless Telegram Mini Apps (TMA)

This project provides a **Telegram Bot** and **3 logical Telegram Mini Apps (WebApps)** to control and monitor OpenWRT routers, AdGuard Home, and Wake-on-LAN hosts.

### 🔒 Zero-Endpoint Security Architecture (No Open Ports!)
By default, **the router does not expose any HTTP/HTTPS port or tunnel to the internet**:
1. **Static Frontend on GitHub Pages**: The [`webapp/`](file:///Users/stuzo/Files/my/telegram-bot-openwrt/webapp/index.html) folder contains pure static HTML/CSS/JS (zero secrets or IPs) and is hosted on GitHub Pages via [`.github/workflows/deploy-pages.yml`](file:///Users/stuzo/Files/my/telegram-bot-openwrt/.github/workflows/deploy-pages.yml).
2. **State via Encrypted/Compressed URL Fragment (`#state=...`)**: When you open `/start` or tap `🔄 Обновить пульт`, the bot queries your routers and AdGuard over the local LAN, compresses a role-filtered snapshot (`gzip` + `base64url` via [`state_codec.py`](file:///Users/stuzo/Files/my/telegram-bot-openwrt/state_codec.py)), and embeds it into the `#state=...` URL hash of the Reply Keyboard buttons.
   * *Privacy Guarantee*: Browsers **never** send the `#fragment` part of a URL over HTTP — even GitHub Pages servers never see your router status or device names in logs.
   * *Role Isolation*: Regular whitelisted users only receive Guest Wi-Fi and AdGuard status in their snapshot; admin metrics, client lists, and user lists are omitted.
3. **Commands via `Telegram.WebApp.sendData()`**: When you click any button inside the Mini App, the app sends a signed message back through Telegram's native `WebApp.sendData` channel, which the bot receives over its standard outbound `getUpdates` long-polling connection, executes on the router, and replies with an updated state snapshot!

---

## Logical Division of Telegram Mini Apps

The Mini App is logically divided into **3 specialized apps**, accessible directly from the bot's bottom Reply Keyboard:

1. 🏠 **Home Control App (`?app=home`) — «Домашний пульт»** *(All whitelisted users & admins)*
   - **Guest Wi-Fi**: Live status (`Enabled` / `Disabled`) across all routers and radio interfaces (`wifinet5`, `wifinet6`), SSID display, global toggle ("Enable All" / "Disable All"), and per-router toggles.
   - **AdGuard Home**: Live protection status, real-time countdown timer when paused, DNS filtering statistics (total queries, blocked queries, block percentage, latency), and 1-tap pause buttons (`10m`, `30m`, `60m`).

2. 📡 **Network & Devices App (`?app=network`) — «Сеть и WOL»** *(Admins only)*
   - **OpenWRT Router Monitoring**: CPU Load Average, RAM usage bar (`MB` and `%`), Uptime, router model & firmware version, and safe Router Reboot with confirmation dialog.
   - **Wake-on-LAN (WOL)**: Configured hosts with live **Online / Offline** detection (via router ARP & DHCP tables) and 1-tap Magic Packet wake.
   - **Connected Clients**: Searchable & filterable list of LAN/Wi-Fi devices (`hostname`, `IP`, `MAC`, `online` status).

3. 🔐 **Access & System App (`?app=admin`) — «Доступ»** *(Admins only)*
   - **Role-Based Access Control (RBAC)**: View all authorized users (`Admin` vs `User`), add new Telegram User IDs via an inline form, or revoke access in one tap.

---

## Setup & Deployment

### Step 1: Publish Static Frontend to GitHub Pages
1. Push this repository to GitHub.
2. In your GitHub repository, go to **Settings → Pages → Build and deployment** and select **Source: GitHub Actions**.
3. The included workflow [`.github/workflows/deploy-pages.yml`](file:///Users/stuzo/Files/my/telegram-bot-openwrt/.github/workflows/deploy-pages.yml) will automatically publish `./webapp` to `https://<your-username>.github.io/<repo-name>/`.

### Step 2: Configure `settings.yaml` on OpenWRT
Copy `settings.yaml.example` to `settings.yaml`:

```yaml
bot_token: "YOUR_TELEGRAM_BOT_TOKEN"
admin_user_ids: [123456789]        # Full admin access (Network, WOL, Reboot, Users)

webapp:
  static_url: "https://<your-username>.github.io/<repo-name>/"
  enabled: false                   # false = ZERO open ports on the router!

routers:
  main_router:
    ip: "192.168.1.1"
    username: "root"
    password: "your-router-password"
    guest_network_device: "wifinet5, wifinet6"
```

### Step 3: Run the Bot on OpenWRT
```bash
pip install -r requirements.txt
python3 main.py
```

*(Optional)* For local browser UI preview during development:
```bash
TMA_DEV_MODE=1 python3 main.py --webapp-only
```

## License

This project is licensed under the MIT License.
