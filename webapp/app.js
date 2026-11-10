(function () {
  const tg = window.Telegram && window.Telegram.WebApp ? window.Telegram.WebApp : null;
  if (tg) {
    tg.ready();
    tg.expand();
  }

  // Application state
  const state = {
    serverless: false,
    snapshotTs: 0,
    botUsername: "",
    user: null,
    activeTab: "home",
    wifi: null,
    adguard: null,
    adguardTimerInterval: null,
    adguardRemainingSec: 0,
    routers: [],
    clients: [],
    wolHosts: [],
    clientFilter: "online",
    clientSearch: "",
    unifi: null,
    unifiClientSearch: "",
    adminUsers: [],
  };

  const APP_META = {
    home: {
      icon: "🏠",
      title: "Домашний пульт",
      subtitle: "Гостевой Wi-Fi и защита AdGuard Home",
    },
    network: {
      icon: "📡",
      title: "Сеть и Устройства",
      subtitle: "Мониторинг OpenWrt, клиенты и WOL",
    },
    unifi: {
      icon: "🛜",
      title: "UniFi Controller",
      subtitle: "Точки доступа, SSID, сигнал клиентов и PoE",
    },
    admin: {
      icon: "🔐",
      title: "Доступ и Система",
      subtitle: "Управление белым списком пользователей",
    },
  };

  const $ = (id) => document.getElementById(id);

  function haptic(type = "light") {
    try {
      if (tg && tg.HapticFeedback) {
        if (type === "success" || type === "error" || type === "warning") {
          tg.HapticFeedback.notificationOccurred(type);
        } else {
          tg.HapticFeedback.impactOccurred(type);
        }
      }
    } catch (_) {}
  }

  let toastTimeout = null;
  function showToast(msg) {
    const el = $("toast");
    if (!el) return;
    el.textContent = msg;
    el.hidden = false;
    if (toastTimeout) clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => {
      el.hidden = true;
    }, 3200);
  }

  function askConfirm(title, message) {
    return new Promise((resolve) => {
      const modal = $("confirm-modal");
      $("confirm-title").textContent = title;
      $("confirm-message").textContent = message;
      modal.hidden = false;

      const cleanup = (result) => {
        modal.hidden = true;
        $("confirm-cancel-btn").onclick = null;
        $("confirm-ok-btn").onclick = null;
        resolve(result);
      };

      $("confirm-cancel-btn").onclick = () => cleanup(false);
      $("confirm-ok-btn").onclick = () => cleanup(true);
    });
  }

  // ---------------- URL Hash State Decoder (Serverless Mode) ----------------
  function base64UrlToUint8Array(b64url) {
    const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
    const b64 = (b64url + pad).replace(/-/g, "+").replace(/_/g, "/");
    const binStr = atob(b64);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      bytes[i] = binStr.charCodeAt(i);
    }
    return bytes;
  }

  function uint8ArrayToBase64Url(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function decodeStateToken(token) {
    if (!token) return null;
    if (token.startsWith("j.")) {
      const bytes = base64UrlToUint8Array(token.slice(2));
      const text = new TextDecoder("utf-8").decode(bytes);
      return JSON.parse(text);
    }
    if (token.startsWith("z.")) {
      const compressed = base64UrlToUint8Array(token.slice(2));
      if (typeof DecompressionStream !== "undefined") {
        const ds = new DecompressionStream("gzip");
        const writer = ds.writable.getWriter();
        writer.write(compressed);
        writer.close();
        const resp = new Response(ds.readable);
        const text = await resp.text();
        return JSON.parse(text);
      }
      throw new Error("Ваш браузер не поддерживает распаковку gzip (DecompressionStream)");
    }
    return null;
  }

  function extractHashStateToken() {
    // 1. Prefer query parameter (?app=home&state=...) so location.hash stays reserved for Telegram's #tgWebAppData
    const searchParams = new URLSearchParams(window.location.search);
    const qState = searchParams.get("state");
    if (qState) {
      return qState.split("#")[0];
    }

    // 2. Fallback: support #state=... (even if Telegram appended a second #tgWebAppData=...)
    const rawHash = window.location.hash.replace(/^#/, "");
    if (!rawHash) return null;
    const firstFragment = rawHash.split("#")[0];
    const params = new URLSearchParams(firstFragment);
    const hState = params.get("state");
    return hState ? hState.split("#")[0] : null;
  }

  function resolveTelegramContext() {
    let user = tg && tg.initDataUnsafe && tg.initDataUnsafe.user ? tg.initDataUnsafe.user : null;
    let platform = tg && tg.platform ? tg.platform : "unknown";

    // If the URL had a double hash (#state=...#tgWebAppData=...), telegram-web-app.js might have missed tgWebAppData
    if (!user && window.location.hash.includes("tgWebAppData=")) {
      const segments = window.location.hash.split("#").filter(Boolean);
      for (const seg of segments) {
        const p = new URLSearchParams(seg);
        if (p.get("tgWebAppPlatform") && platform === "unknown") {
          platform = p.get("tgWebAppPlatform");
        }
        const rawWebAppData = p.get("tgWebAppData");
        if (rawWebAppData) {
          const innerParams = new URLSearchParams(rawWebAppData);
          const userJson = innerParams.get("user");
          if (userJson) {
            try {
              user = JSON.parse(userJson);
            } catch (_) {}
          }
        }
      }
    }

    const isInsideTelegram = Boolean(
      (user && user.id) || (platform && platform !== "unknown")
    );
    return { user, platform, isInsideTelegram };
  }

  // ---------------- Background Encrypted RPC Bridge (No App Close / No Chat Spam) ----------------
  async function sha256Bytes(uint8Arr) {
    const hashBuf = await crypto.subtle.digest("SHA-256", uint8Arr);
    return new Uint8Array(hashBuf);
  }

  function bytesToHex(bytes) {
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  }

  async function xorKeystream(dataBytes, keyStr, nonceStr) {
    const out = new Uint8Array(dataBytes.length);
    const blockCount = Math.ceil(dataBytes.length / 32);
    const enc = new TextEncoder();
    for (let i = 0; i < blockCount; i++) {
      const seed = enc.encode(`${keyStr}:${nonceStr}:${i}`);
      const ks = await sha256Bytes(seed);
      const start = i * 32;
      const end = Math.min(start + 32, dataBytes.length);
      for (let j = start; j < end; j++) {
        out[j] = dataBytes[j] ^ ks[j - start];
      }
    }
    return out;
  }

  async function encryptRpcPacket(innerText, keyStr) {
    const rand = new Uint8Array(8);
    crypto.getRandomValues(rand);
    const nonceStr = bytesToHex(rand);
    const enc = new TextEncoder();
    const plainBytes = enc.encode(innerText);
    const cipherBytes = await xorKeystream(plainBytes, keyStr, nonceStr);
    const prefixBytes = enc.encode(`${keyStr}:${nonceStr}:mac:`);
    const macInput = new Uint8Array(prefixBytes.length + cipherBytes.length);
    macInput.set(prefixBytes, 0);
    macInput.set(cipherBytes, prefixBytes.length);
    const macHash = await sha256Bytes(macInput);
    const macHex = bytesToHex(macHash).slice(0, 24);
    return `e1.${nonceStr}.${macHex}.${uint8ArrayToBase64Url(cipherBytes)}`;
  }

  async function decryptRpcPacket(packet, keyStr) {
    const parts = String(packet || "").trim().split(".");
    if (parts.length !== 4 || parts[0] !== "e1") return null;
    const [, nonceStr, macHex, b64Cipher] = parts;
    const cipherBytes = base64UrlToUint8Array(b64Cipher);
    const enc = new TextEncoder();
    const prefixBytes = enc.encode(`${keyStr}:${nonceStr}:mac:`);
    const macInput = new Uint8Array(prefixBytes.length + cipherBytes.length);
    macInput.set(prefixBytes, 0);
    macInput.set(cipherBytes, prefixBytes.length);
    const macHash = await sha256Bytes(macInput);
    const expectedMac = bytesToHex(macHash).slice(0, 24);
    if (macHex !== expectedMac) return null;
    const plainBytes = await xorKeystream(cipherBytes, keyStr, nonceStr);
    return new TextDecoder("utf-8").decode(plainBytes);
  }

  function applySnapshotToState(snap) {
    if (!snap) return;
    if (snap.ts) state.snapshotTs = snap.ts;
    if (snap.wifi !== undefined) state.wifi = snap.wifi;
    if (snap.adguard !== undefined) state.adguard = snap.adguard;
    if (snap.routers !== undefined) state.routers = snap.routers || [];
    if (snap.clients !== undefined) state.clients = snap.clients || [];
    if (snap.wol_hosts !== undefined) state.wolHosts = snap.wol_hosts || [];
    if (snap.unifi !== undefined) state.unifi = snap.unifi;
    if (snap.admin_users !== undefined) state.adminUsers = snap.admin_users || [];

    // Unlock full bottom tab navigation once complete snapshot arrives via RPC
    if (state.user && state.user.is_admin && snap.routers !== undefined) {
      state.scopedApp = null;
      $("nav-tab-network").hidden = false;
      $("nav-tab-unifi").hidden = !(state.unifi && state.unifi.configured);
      $("nav-tab-admin").hidden = false;
      $("bottom-nav").hidden = false;
    }

    const age = formatSnapshotAge(state.snapshotTs);
    $("app-subtitle").textContent = `🔒 Без эндпоинта${age ? " • " + age : ""}`;
    if (state.activeTab === "home") renderHome();
    else if (state.activeTab === "network") renderNetwork();
    else if (state.activeTab === "unifi") renderUnifi();
    else if (state.activeTab === "admin") renderAdmin();
  }

  function waitForRpcReply(relayBase, resTopic, timeoutMs = 14000) {
    return new Promise((resolve, reject) => {
      let settled = false;
      let es = null;
      const pollTimers = [];

      const finish = (err, msg) => {
        if (settled) return;
        settled = true;
        clearTimeout(mainTimer);
        pollTimers.forEach((t) => clearTimeout(t));
        if (es) {
          try {
            es.close();
          } catch (_) {}
        }
        if (err) reject(err);
        else resolve(msg);
      };

      const mainTimer = setTimeout(() => {
        finish(new Error("Превышено время ожидания ответа от роутера"));
      }, timeoutMs);

      // 1. Real-time SSE stream
      if (typeof EventSource !== "undefined") {
        try {
          es = new EventSource(`${relayBase}/${resTopic}/sse?since=all`);
          es.onmessage = (ev) => {
            try {
              const data = JSON.parse(ev.data);
              if (data && data.message && String(data.message).startsWith("e1.")) {
                finish(null, data.message);
              }
            } catch (_) {}
          };
        } catch (_) {}
      }

      // 2. Parallel HTTP poll fallback (in case mobile network buffers SSE)
      const pollOnce = async () => {
        if (settled) return;
        try {
          const resp = await fetch(`${relayBase}/${resTopic}/json?poll=1&since=all`);
          if (!resp.ok) return;
          const text = await resp.text();
          const lines = text.split("\n").filter(Boolean);
          for (const line of lines) {
            try {
              const obj = JSON.parse(line);
              if (obj && obj.message && String(obj.message).startsWith("e1.")) {
                finish(null, obj.message);
                return;
              }
            } catch (_) {}
          }
        } catch (_) {}
      };
      pollTimers.push(setTimeout(pollOnce, 1100));
      pollTimers.push(setTimeout(pollOnce, 2600));
      pollTimers.push(setTimeout(pollOnce, 5000));
      pollTimers.push(setTimeout(pollOnce, 8500));
    });
  }

  async function executeRpcCommand(cmdPayload, options = {}) {
    if (!state.rpc || !state.rpc.topic || !state.rpc.key) {
      return false;
    }
    const silent = Boolean(options.silent);
    const refreshBtn = $("refresh-btn");
    if (refreshBtn) refreshBtn.classList.add("spinning");
    if (!silent) {
      haptic("light");
      showToast("⏳ Выполняется...");
    }

    try {
      const randBytes = new Uint8Array(6);
      crypto.getRandomValues(randBytes);
      const reqId = bytesToHex(randBytes);
      const relayBase = (state.rpc.relay || "https://ntfy.sh").replace(/\/+$/, "");
      const resTopic = `owrt_r_${reqId}`;

      const fullReq = Object.assign({}, cmdPayload, {
        req_id: reqId,
        ts: Math.floor(Date.now() / 1000),
        user_id: state.user ? state.user.user_id : 0,
        first_name: state.user ? state.user.first_name || "" : "",
        username: state.user ? state.user.username || "" : "",
      });

      const encryptedReq = await encryptRpcPacket(
        JSON.stringify(fullReq),
        state.rpc.key
      );

      // Start listening before POST so fast replies are never missed
      const replyPromise = waitForRpcReply(relayBase, resTopic, 14000);

      await fetch(`${relayBase}/${state.rpc.topic}`, {
        method: "POST",
        body: encryptedReq,
      });

      const encryptedReply = await replyPromise;
      const compressedToken = await decryptRpcPacket(
        encryptedReply,
        state.rpc.key
      );
      if (!compressedToken) {
        throw new Error("Не удалось расшифровать ответ от роутера");
      }
      const res = await decodeStateToken(compressedToken);
      if (!res || res.ok === false) {
        throw new Error((res && res.error) || "Ошибка выполнения команды");
      }

      if (res.snapshot) {
        applySnapshotToState(res.snapshot);
      }
      if (!silent) {
        haptic("success");
        showToast(res.message || "✅ Обновлено");
      }
      return true;
    } catch (err) {
      if (!silent) {
        haptic("error");
        showToast(err.message || "Ошибка связи с роутером");
      }
      return false;
    } finally {
      if (refreshBtn) refreshBtn.classList.remove("spinning");
    }
  }

  // ---------------- Serverless Action Dispatcher ----------------
  function sendServerlessCommand(cmdPayload) {
    // 1. Primary path: Background Encrypted RPC Bridge (stays inside Mini App, ZERO chat messages!)
    if (state.rpc && state.rpc.topic && state.rpc.key) {
      const action = cmdPayload && cmdPayload.action === "refresh_state"
        ? Object.assign({}, cmdPayload, { action: "get_state" })
        : cmdPayload;
      executeRpcCommand(action);
      return true;
    }

    // 2. Legacy Fallback if RPC bridge is disabled in settings.yaml
    const jsonStr = JSON.stringify(cmdPayload);
    const isInlineMode = Boolean(tg && tg.initDataUnsafe && tg.initDataUnsafe.query_id);
    if (tg && typeof tg.sendData === "function" && !isInlineMode) {
      haptic("success");
      tg.sendData(jsonStr);
      return true;
    }

    if (state.botUsername) {
      const encoded = uint8ArrayToBase64Url(new TextEncoder().encode(jsonStr));
      const deepLink = `https://t.me/${state.botUsername}?start=cmd_${encoded}`;
      if (tg && typeof tg.openTelegramLink === "function") {
        tg.openTelegramLink(deepLink);
        if (typeof tg.close === "function") tg.close();
        return true;
      }
      window.location.href = deepLink;
      return true;
    }

    showToast("Не удалось отправить команду.");
    return false;
  }

  // ---------------- Local API Call (When Local Server Mode is used) ----------------
  async function apiCall(path, options = {}) {
    const headers = Object.assign(
      { "Content-Type": "application/json" },
      options.headers || {}
    );
    if (tg && tg.initData) {
      headers["X-Telegram-Init-Data"] = tg.initData;
    }

    const resp = await fetch(path, {
      method: options.method || "GET",
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    const data = await resp.json().catch(() => ({ ok: false, error: `HTTP ${resp.status}` }));
    if (!resp.ok || data.ok === false) {
      const err = new Error(data.error || `Ошибка запроса (${resp.status})`);
      err.status = resp.status;
      err.payload = data;
      throw err;
    }
    return data;
  }

  function detectInitialApp() {
    const validTabs = ["home", "network", "unifi", "admin"];
    const path = window.location.pathname.replace(/^\/+|\/+$/g, "");
    if (validTabs.includes(path)) {
      return path;
    }
    const params = new URLSearchParams(window.location.search);
    const qApp = params.get("app") || params.get("mode") || params.get("tab");
    if (validTabs.includes(qApp)) {
      return qApp;
    }
    const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ""));
    const hApp = hashParams.get("app");
    if (validTabs.includes(hApp)) {
      return hApp;
    }
    const startParam = tg && tg.initDataUnsafe && tg.initDataUnsafe.start_param;
    if (validTabs.includes(startParam)) {
      return startParam;
    }
    return "home";
  }

  // ---------------- Formatters ----------------
  function formatUptime(sec) {
    sec = Number(sec || 0);
    if (sec <= 0) return "—";
    const d = Math.floor(sec / 86400);
    const h = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    if (d > 0) return `${d}д ${h}ч`;
    if (h > 0) return `${h}ч ${m}м`;
    return `${m} мин`;
  }

  function formatBytesMB(bytes) {
    const mb = Number(bytes || 0) / (1024 * 1024);
    return `${Math.round(mb)} МБ`;
  }

  function formatCountdown(sec) {
    sec = Math.max(0, Math.floor(sec));
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return `${m}:${s < 10 ? "0" : ""}${s}`;
  }

  function formatSnapshotAge(ts) {
    if (!ts) return "";
    const diffSec = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (diffSec < 60) return "актуально (только что)";
    const mins = Math.floor(diffSec / 60);
    if (mins < 60) return `снимок ${mins} мин назад`;
    const hours = Math.floor(mins / 60);
    return `снимок ${hours} ч назад`;
  }

  function escapeHtml(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // ---------------- Screen & Tab Switching ----------------
  async function switchTab(tabName) {
    if (!state.user || !state.user.is_authorized) return;
    if ((tabName === "network" || tabName === "unifi" || tabName === "admin") && !state.user.is_admin) {
      tabName = "home";
    }
    state.activeTab = tabName;

    const meta = APP_META[tabName] || APP_META.home;
    $("app-icon").textContent = meta.icon;
    $("app-title").textContent = meta.title;
    if (state.serverless) {
      const age = formatSnapshotAge(state.snapshotTs);
      $("app-subtitle").textContent = `🔒 Без эндпоинта${age ? " • " + age : ""}`;
    } else {
      $("app-subtitle").textContent = meta.subtitle;
    }

    $("screen-unauthorized").hidden = true;
    $("screen-home").hidden = tabName !== "home";
    $("screen-network").hidden = tabName !== "network";
    $("screen-unifi").hidden = tabName !== "unifi";
    $("screen-admin").hidden = tabName !== "admin";

    document.querySelectorAll(".nav-tab").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.tab === tabName);
    });

    await refreshCurrentTab();
  }

  async function refreshCurrentTab(manualTrigger = false) {
    if (state.serverless) {
      if (manualTrigger) {
        sendServerlessCommand({ action: "refresh_state", tab: state.activeTab });
        return;
      }
      if (state.activeTab === "home") renderHome();
      else if (state.activeTab === "network") renderNetwork();
      else if (state.activeTab === "unifi") renderUnifi();
      else if (state.activeTab === "admin") renderAdmin();
      return;
    }

    const refreshBtn = $("refresh-btn");
    refreshBtn.classList.add("spinning");
    try {
      if (state.activeTab === "home") {
        const res = await apiCall("/api/home");
        state.wifi = res.wifi;
        state.adguard = res.adguard;
        renderHome();
      } else if (state.activeTab === "network") {
        const res = await apiCall("/api/network");
        state.routers = res.routers || [];
        state.clients = res.clients || [];
        state.wolHosts = res.wol_hosts || [];
        renderNetwork();
      } else if (state.activeTab === "unifi") {
        renderUnifi();
      } else if (state.activeTab === "admin") {
        const res = await apiCall("/api/admin/users");
        state.adminUsers = res.users || [];
        renderAdmin();
      }
    } catch (err) {
      showToast(err.message || "Ошибка обновления данных");
    } finally {
      refreshBtn.classList.remove("spinning");
    }
  }

  // ---------------- Render: HOME APP ----------------
  function renderHome() {
    renderWifiSection(state.wifi);
    renderAdguardSection(state.adguard);
  }

  function renderWifiSection(wifi) {
    if (!wifi) return;
    const badge = $("wifi-global-badge");
    const sub = $("wifi-summary-subtitle");
    const ssidsBox = $("wifi-ssids-box");
    const platformsWrap = $("home-guest-platforms-wrap");
    const platformsList = $("home-guest-platforms-list");

    const routers = wifi.routers || [];
    const okRouters = routers.filter((r) => r.ok);
    const owrtOn = okRouters.some((r) => r.enabled);

    const guestWlans =
      state.unifi && state.unifi.wlans
        ? state.unifi.wlans.filter((w) => w.is_guest)
        : [];
    const hasUnifiGuest = guestWlans.length > 0;
    const unifiOn = guestWlans.some((w) => w.enabled);

    const anyOn = owrtOn || unifiOn;
    const allOn = owrtOn && (!hasUnifiGuest || unifiOn);

    if (okRouters.length === 0 && routers.length > 0 && !hasUnifiGuest) {
      badge.className = "status-badge status-err";
      badge.textContent = "Ошибка связи";
      sub.textContent = "Роутеры недоступны по RPC";
    } else if (allOn && anyOn) {
      badge.className = "status-badge status-on";
      badge.textContent = "Включен";
      sub.textContent = hasUnifiGuest
        ? "Гостевая сеть активна на OpenWrt и UniFi"
        : "Гостевая сеть активна на роутере OpenWrt";
    } else if (anyOn) {
      badge.className = "status-badge status-warn";
      badge.textContent = "Частично";
      sub.textContent = `OpenWrt: ${owrtOn ? "Вкл" : "Выкл"}${hasUnifiGuest ? " • UniFi: " + (unifiOn ? "Вкл" : "Выкл") : ""}`;
    } else {
      badge.className = "status-badge status-off";
      badge.textContent = "Выключен";
      sub.textContent = "Гостевая сеть отключена везде";
    }

    const allSsids = [...(wifi.ssids || [])];
    guestWlans.forEach((w) => {
      if (w.name && !allSsids.includes(w.name)) allSsids.push(w.name);
    });

    if (allSsids.length > 0) {
      ssidsBox.hidden = false;
      ssidsBox.innerHTML = allSsids
        .map((s) => `<span class="ssid-pill">📶 SSID: <strong>${escapeHtml(s)}</strong></span>`)
        .join("");
    } else {
      ssidsBox.hidden = true;
    }

    if (platformsWrap && platformsList) {
      const itemsHtml = [];

      // 1. OpenWrt Guest summary row (no individual radio modules list)
      if (routers.length > 0) {
        const owrtSsids = (wifi.ssids || []).join(", ") || "guest";
        const nextAct = owrtOn ? "off" : "on";
        itemsHtml.push(`
          <div class="list-item">
            <div class="list-item-row">
              <div>
                <div class="item-title">
                  📡 Роутер OpenWrt
                  <span class="status-badge ${owrtOn ? "status-on" : "status-off"}">
                    ${owrtOn ? "Вкл" : "Выкл"}
                  </span>
                </div>
                <div class="item-meta">Гостевая сеть: ${escapeHtml(owrtSsids)}</div>
              </div>
              <button class="btn btn-sm ${owrtOn ? "btn-secondary" : "btn-success"}"
                data-platform-wifi="openwrt" data-action="${nextAct}">
                ${owrtOn ? "Выключить" : "Включить"}
              </button>
            </div>
          </div>
        `);
      }

      // 2. UniFi Guest summary row
      if (hasUnifiGuest) {
        const uNames = guestWlans.map((w) => w.name).join(", ");
        const nextAct = unifiOn ? "off" : "on";
        itemsHtml.push(`
          <div class="list-item">
            <div class="list-item-row">
              <div>
                <div class="item-title">
                  🛜 Точки UniFi
                  <span class="status-badge ${unifiOn ? "status-on" : "status-off"}">
                    ${unifiOn ? "Вкл" : "Выкл"}
                  </span>
                </div>
                <div class="item-meta">Гостевая сеть: ${escapeHtml(uNames)}</div>
              </div>
              <button class="btn btn-sm ${unifiOn ? "btn-secondary" : "btn-success"}"
                data-platform-wifi="unifi" data-action="${nextAct}">
                ${unifiOn ? "Выключить" : "Включить"}
              </button>
            </div>
          </div>
        `);
      }

      if (itemsHtml.length > 0) {
        platformsWrap.hidden = false;
        platformsList.innerHTML = itemsHtml.join("");
        platformsList.querySelectorAll("[data-platform-wifi]").forEach((btn) => {
          btn.onclick = () =>
            handleWifiToggle(btn.dataset.action, btn.dataset.platformWifi, btn);
        });
      } else {
        platformsWrap.hidden = true;
      }
    }
  }

  async function handleWifiToggle(action, router = "all", btnEl = null) {
    if (state.serverless) {
      sendServerlessCommand({ action: "wifi_toggle", mode: action, router });
      return;
    }
    haptic("medium");
    if (btnEl) btnEl.disabled = true;
    $("btn-wifi-all-on").disabled = true;
    $("btn-wifi-all-off").disabled = true;
    try {
      const res = await apiCall("/api/wifi/toggle", {
        method: "POST",
        body: { action, router },
      });
      state.wifi = res.wifi;
      renderWifiSection(state.wifi);
      haptic("success");
      showToast(
        action === "on"
          ? "Гостевой Wi-Fi включен ✅"
          : "Гостевой Wi-Fi выключен 🌙"
      );
    } catch (err) {
      haptic("error");
      showToast(err.message);
    } finally {
      if (btnEl) btnEl.disabled = false;
      $("btn-wifi-all-on").disabled = false;
      $("btn-wifi-all-off").disabled = false;
    }
  }

  function renderAdguardSection(ag) {
    if (!ag) return;
    const badge = $("adguard-status-badge");
    const sub = $("adguard-summary-subtitle");
    const timerBanner = $("adguard-timer-banner");
    const statsGrid = $("adguard-stats-grid");
    const controls = $("adguard-controls");

    if (state.adguardTimerInterval) {
      clearInterval(state.adguardTimerInterval);
      state.adguardTimerInterval = null;
    }

    if (!ag.configured) {
      badge.className = "status-badge status-off";
      badge.textContent = "Не настроен";
      sub.textContent = "Секция adguard не задана в settings.yaml";
      timerBanner.hidden = true;
      statsGrid.hidden = true;
      controls.hidden = true;
      return;
    }

    if (!ag.ok) {
      badge.className = "status-badge status-err";
      badge.textContent = "Ошибка";
      sub.textContent = ag.error || "AdGuard Home недоступен";
      timerBanner.hidden = true;
      statsGrid.hidden = true;
      controls.hidden = false;
      return;
    }

    controls.hidden = false;
    if (ag.enabled) {
      badge.className = "status-badge status-on";
      badge.textContent = "Защита активна";
      sub.textContent = ag.version
        ? `AdGuard Home ${ag.version} • Фильтрация работает`
        : "DNS-фильтрация активна";
      timerBanner.hidden = true;
    } else {
      badge.className = "status-badge status-warn";
      badge.textContent = "На паузе";
      sub.textContent = "Фильтрация временно отключена";

      let remMs = Number(ag.disabled_duration_ms || 0);
      if (state.serverless && state.snapshotTs > 0 && remMs > 0) {
        const elapsedMs = Math.max(0, Date.now() - state.snapshotTs * 1000);
        remMs = Math.max(0, remMs - elapsedMs);
      }

      if (remMs > 0) {
        timerBanner.hidden = false;
        state.adguardRemainingSec = Math.ceil(remMs / 1000);
        $("adguard-countdown").textContent = `Авто-включение через ${formatCountdown(state.adguardRemainingSec)}`;
        state.adguardTimerInterval = setInterval(() => {
          state.adguardRemainingSec -= 1;
          if (state.adguardRemainingSec <= 0) {
            clearInterval(state.adguardTimerInterval);
            $("adguard-countdown").textContent = "Таймер истёк (защита включена)";
          } else {
            $("adguard-countdown").textContent = `Авто-включение через ${formatCountdown(state.adguardRemainingSec)}`;
          }
        }, 1000);
      } else {
        timerBanner.hidden = false;
        $("adguard-countdown").textContent = "Отключена до ручного включения";
      }
    }

    if (ag.stats && typeof ag.stats.dns_queries === "number") {
      statsGrid.hidden = false;
      $("ag-stat-queries").textContent = ag.stats.dns_queries.toLocaleString("ru-RU");
      $("ag-stat-blocked").textContent = ag.stats.blocked_filtering.toLocaleString("ru-RU");
      $("ag-stat-percent").textContent = `${ag.stats.blocked_percent}%`;
      $("ag-stat-latency").textContent = `${ag.stats.avg_processing_ms} мс`;
    } else {
      statsGrid.hidden = true;
    }
  }

  async function handleAdguardToggle(enabled, durationMinutes = null) {
    if (state.serverless) {
      sendServerlessCommand({
        action: "adguard_toggle",
        enabled,
        duration_minutes: durationMinutes,
      });
      return;
    }
    haptic("medium");
    try {
      const res = await apiCall("/api/adguard/toggle", {
        method: "POST",
        body: { enabled, duration_minutes: durationMinutes },
      });
      state.adguard = res.adguard;
      renderAdguardSection(state.adguard);
      haptic("success");
      showToast(
        enabled
          ? "Защита AdGuard включена 🛡️"
          : `AdGuard на паузе (${durationMinutes} мин) ⏸️`
      );
    } catch (err) {
      haptic("error");
      showToast(err.message);
    }
  }

  // ---------------- Render: NETWORK & DEVICES APP ----------------
  function renderNetwork() {
    renderRoutersMonitoring();
    renderWolSection();
    renderClientsList();
  }

  function renderRoutersMonitoring() {
    const container = $("network-routers-list");
    if (!state.routers.length) {
      container.innerHTML = `<div class="item-meta">Роутеры не найдены</div>`;
      return;
    }

    container.innerHTML = state.routers
      .map((r) => {
        if (!r.ok) {
          return `
            <div class="list-item">
              <div class="list-item-row">
                <div class="item-title">📡 ${escapeHtml(r.name)} (${escapeHtml(r.ip)})</div>
                <span class="status-badge status-err">Офлайн</span>
              </div>
              <div class="item-meta">${escapeHtml(r.error || "Ошибка связи")}</div>
            </div>
          `;
        }
        const mem = r.memory || {};
        const load = (r.load_avg || [0, 0, 0]).join(" / ");
        return `
          <div class="list-item">
            <div class="list-item-row">
              <div>
                <div class="item-title">
                  📡 ${escapeHtml(r.hostname || r.name)}
                  <span class="status-badge status-on">Онлайн</span>
                </div>
                <div class="item-meta">
                  ${escapeHtml(r.model)} • ${escapeHtml(r.version)} • ${escapeHtml(r.ip)}
                </div>
              </div>
              <button class="btn btn-sm btn-danger-soft" data-reboot-router="${escapeHtml(r.name)}">
                🔄 Ребут
              </button>
            </div>

            <div class="metrics-grid">
              <div class="metric-chip">
                <span class="metric-chip-label">Uptime</span>
                <span class="metric-chip-val">${formatUptime(r.uptime_seconds)}</span>
              </div>
              <div class="metric-chip">
                <span class="metric-chip-label">CPU Load</span>
                <span class="metric-chip-val">${escapeHtml(load)}</span>
              </div>
              <div class="metric-chip">
                <span class="metric-chip-label">Клиенты</span>
                <span class="metric-chip-val">${r.clients_count || 0} онлайн</span>
              </div>
            </div>

            <div>
              <div class="list-item-row" style="font-size: 12px;">
                <span class="item-meta">Память (RAM)</span>
                <span><strong>${formatBytesMB(mem.used_bytes)}</strong> / ${formatBytesMB(mem.total_bytes)} (${mem.percent || 0}%)</span>
              </div>
              <div class="progress-bar-wrap">
                <div class="progress-bar-fill" style="width: ${Math.min(100, mem.percent || 0)}%"></div>
              </div>
            </div>
          </div>
        `;
      })
      .join("");

    container.querySelectorAll("[data-reboot-router]").forEach((btn) => {
      btn.onclick = async () => {
        const rname = btn.dataset.rebootRouter;
        const confirmed = await askConfirm(
          `Перезагрузить ${rname}?`,
          `Роутер ${rname} будет перезагружен. Соединение Wi-Fi и интернет временно прервутся на 1–2 минуты.`
        );
        if (!confirmed) return;
        if (state.serverless) {
          sendServerlessCommand({ action: "router_reboot", router: rname });
          return;
        }
        haptic("heavy");
        btn.disabled = true;
        try {
          const res = await apiCall("/api/routers/reboot", {
            method: "POST",
            body: { router: rname },
          });
          haptic("success");
          showToast(res.message || `Перезагрузка ${rname} запущена`);
        } catch (err) {
          haptic("error");
          showToast(err.message);
        } finally {
          btn.disabled = false;
        }
      };
    });
  }

  function renderWolSection() {
    const container = $("wol-hosts-list");
    if (!state.wolHosts.length) {
      container.innerHTML = `<div class="item-meta">Нет хостов в wake_on_lan_hosts (settings.yaml)</div>`;
      return;
    }

    container.innerHTML = state.wolHosts
      .map((h) => {
        const statusBadge = h.online
          ? `<span class="status-badge status-on">🟢 В сети${h.detected_ip ? " (" + escapeHtml(h.detected_ip) + ")" : ""}</span>`
          : `<span class="status-badge status-off">⚪ Спит / Офлайн</span>`;
        return `
          <div class="list-item">
            <div class="list-item-row">
              <div>
                <div class="item-title">
                  🖥️ ${escapeHtml(h.name)}
                  ${statusBadge}
                </div>
                <div class="item-meta">MAC: <code>${escapeHtml(h.mac || "не задан")}</code></div>
              </div>
              <button class="btn btn-sm btn-primary" data-wol-host="${escapeHtml(h.name)}">
                ⚡ Разбудить
              </button>
            </div>
          </div>
        `;
      })
      .join("");

    container.querySelectorAll("[data-wol-host]").forEach((btn) => {
      btn.onclick = async () => {
        const host = btn.dataset.wolHost;
        if (state.serverless) {
          sendServerlessCommand({ action: "wol_wake", host });
          return;
        }
        haptic("medium");
        btn.disabled = true;
        try {
          const res = await apiCall("/api/wol/wake", {
            method: "POST",
            body: { host },
          });
          haptic("success");
          showToast(res.message || `WOL отправлен на ${host}`);
        } catch (err) {
          haptic("error");
          showToast(err.message);
        } finally {
          btn.disabled = false;
        }
      };
    });
  }

  function renderClientsList() {
    const container = $("network-clients-list");
    const sub = $("clients-count-subtitle");
    const onlineTotal = state.clients.filter((c) => c.online).length;
    sub.textContent = `Онлайн: ${onlineTotal} • Всего: ${state.clients.length}`;

    const q = state.clientSearch.trim().toLowerCase();
    const filtered = state.clients.filter((c) => {
      if (state.clientFilter === "online" && !c.online) return false;
      if (!q) return true;
      return (
        (c.hostname || "").toLowerCase().includes(q) ||
        (c.ip || "").toLowerCase().includes(q) ||
        (c.mac || "").toLowerCase().includes(q) ||
        (c.essid || "").toLowerCase().includes(q) ||
        (c.ap_name || "").toLowerCase().includes(q)
      );
    });

    if (!filtered.length) {
      container.innerHTML = `<div class="item-meta" style="padding: 8px 2px;">Клиенты не найдены</div>`;
      return;
    }

    container.innerHTML = filtered
      .map((c) => {
        const isWifi = Boolean(c.essid || (c.signal_dbm !== undefined && c.signal_dbm !== null));
        let connBadge = "";
        if (isWifi && c.signal_dbm !== undefined && c.signal_dbm !== null) {
          const s = Number(c.signal_dbm);
          const cls = s >= -65 ? "status-on" : s >= -75 ? "status-warn" : "status-err";
          connBadge = `<span class="status-badge ${cls}">📶 ${s} dBm</span>`;
        } else if (isWifi) {
          connBadge = `<span class="status-badge status-on">📶 Wi-Fi</span>`;
        } else {
          connBadge = `<span class="status-badge status-off">🔌 LAN</span>`;
        }

        const blockBadge = c.blocked
          ? `<span class="status-badge status-err">🚫 Заблокирован</span>`
          : "";

        const wifiDetail = c.essid
          ? `${escapeHtml(c.essid)}${c.ap_name ? " → <strong>" + escapeHtml(c.ap_name) + "</strong>" : ""} • `
          : "";

        return `
          <div class="list-item">
            <div class="list-item-row" style="align-items:flex-start;gap:10px;">
              <div style="min-width:0;flex:1;">
                <div class="item-title" style="flex-wrap:wrap;gap:6px;">
                  <span class="dot ${c.online ? "dot-online" : "dot-offline"}"></span>
                  <span style="word-break:break-all;">${escapeHtml(c.hostname)}</span>
                  ${connBadge}
                  ${blockBadge}
                </div>
                <div class="item-meta" style="margin-top:4px;">
                  ${wifiDetail}${escapeHtml(c.ip)} • <code>${escapeHtml(c.mac)}</code>
                </div>
              </div>
              <div style="display:flex;gap:6px;flex-shrink:0;flex-wrap:wrap;justify-content:flex-end;">
                ${
                  isWifi && c.online
                    ? `<button class="btn btn-sm btn-secondary"
                        data-c-kick="${escapeHtml(c.mac)}"
                        data-c-name="${escapeHtml(c.hostname)}"
                        title="Переподключить Wi-Fi">🔄 Kick</button>`
                    : ""
                }
                ${
                  !c.online
                    ? `<button class="btn btn-sm btn-primary"
                        data-c-wol="${escapeHtml(c.mac)}"
                        data-c-name="${escapeHtml(c.hostname)}"
                        title="Wake-on-LAN">⚡ WOL</button>`
                    : ""
                }
                <button class="btn btn-sm ${c.blocked ? "btn-success" : "btn-danger-soft"}"
                  data-c-block="${escapeHtml(c.mac)}"
                  data-c-name="${escapeHtml(c.hostname)}"
                  data-c-block-state="${c.blocked ? "false" : "true"}">
                  ${c.blocked ? "✅ Разблок" : "🚫 Блок"}
                </button>
              </div>
            </div>
          </div>
        `;
      })
      .join("");

    container.querySelectorAll("[data-c-kick]").forEach((btn) => {
      btn.onclick = () =>
        sendServerlessCommand({
          action: "client_kick",
          mac: btn.dataset.cKick,
          hostname: btn.dataset.cName,
        });
    });

    container.querySelectorAll("[data-c-wol]").forEach((btn) => {
      btn.onclick = () =>
        sendServerlessCommand({
          action: "client_wol",
          mac: btn.dataset.cWol,
          hostname: btn.dataset.cName,
        });
    });

    container.querySelectorAll("[data-c-block]").forEach((btn) => {
      btn.onclick = async () => {
        const cname = btn.dataset.cName;
        const shouldBlock = btn.dataset.cBlockState === "true";
        if (shouldBlock) {
          const ok = await askConfirm(
            `Заблокировать интернет для ${cname}?`,
            `Устройству «${cname}» (${btn.dataset.cBlock}) будет заблокирован доступ в интернет на роутере OpenWrt.`
          );
          if (!ok) return;
        }
        sendServerlessCommand({
          action: "client_block",
          mac: btn.dataset.cBlock,
          hostname: cname,
          block: shouldBlock,
        });
      };
    });
  }

  // ---------------- Render: UNIFI CONTROLLER APP ----------------
  function renderUnifi() {
    const u = state.unifi;
    const wlansEl = $("unifi-wlans-list");
    const devsEl = $("unifi-devices-list");

    if (!u || !u.configured) {
      wlansEl.innerHTML = `<div class="item-meta">Секция unifi не настроена в settings.yaml</div>`;
      devsEl.innerHTML = `<div class="item-meta">Нет данных</div>`;
      return;
    }

    if (!u.ok) {
      const errMsg = escapeHtml(u.error || "Ошибка подключения к UniFi Controller");
      wlansEl.innerHTML = `<div class="item-meta">⚠️ ${errMsg}</div>`;
      devsEl.innerHTML = `<div class="item-meta">⚠️ ${errMsg}</div>`;
      return;
    }

    // 1. Render UniFi WLANs
    const wlans = u.wlans || [];
    $("unifi-wlans-subtitle").textContent = `Активно ${wlans.filter((w) => w.enabled).length} из ${wlans.length} SSID`;
    if (!wlans.length) {
      wlansEl.innerHTML = `<div class="item-meta">Wi-Fi сети в UniFi не найдены</div>`;
    } else {
      wlansEl.innerHTML = wlans
        .map(
          (w) => `
          <div class="list-item">
            <div class="list-item-row">
              <div>
                <div class="item-title">
                  📶 ${escapeHtml(w.name)}
                  <span class="status-badge ${w.enabled ? "status-on" : "status-off"}">
                    ${w.enabled ? "Вкл" : "Выкл"}
                  </span>
                  ${w.is_guest ? `<span class="status-badge status-neutral">Guest</span>` : ""}
                </div>
                <div class="item-meta">Диапазон: ${escapeHtml(w.band)} • Защита: ${escapeHtml(w.security)}</div>
              </div>
              <button class="btn btn-sm ${w.enabled ? "btn-secondary" : "btn-success"}"
                data-u-wlan="${escapeHtml(w.id)}"
                data-u-wlan-name="${escapeHtml(w.name)}"
                data-u-enabled="${w.enabled ? "false" : "true"}">
                ${w.enabled ? "Выключить" : "Включить"}
              </button>
            </div>
          </div>
        `
        )
        .join("");

      wlansEl.querySelectorAll("[data-u-wlan]").forEach((btn) => {
        btn.onclick = () =>
          sendServerlessCommand({
            action: "unifi_wlan_toggle",
            wlan_id: btn.dataset.uWlan,
            name: btn.dataset.uWlanName,
            enabled: btn.dataset.uEnabled === "true",
          });
      });
    }

    // 2. Render UniFi APs & Switches
    const devs = u.devices || [];
    if (!devs.length) {
      devsEl.innerHTML = `<div class="item-meta">Точки доступа и свитчи не найдены</div>`;
    } else {
      devsEl.innerHTML = devs
        .map((d) => {
          const nextLed = d.led_override === "off" ? "on" : "off";
          const ledLabel = d.led_override === "off" ? "💡 Вкл LED" : "🌑 Выкл LED";
          const poeHtml =
            d.poe_ports && d.poe_ports.length > 0
              ? `
              <div class="divider" style="margin:8px 0;"></div>
              <div class="sub-label">PoE-порты</div>
              <div class="stack-list">
                ${d.poe_ports
                  .map(
                    (p) => `
                  <div class="client-row">
                    <div>
                      <div style="font-weight:600;font-size:13px;">
                        🔌 #${p.port_idx} ${escapeHtml(p.name)}
                      </div>
                      <div class="item-meta">
                        ${p.up ? "🟢 Активен" : "⚪ Не подключен"} • Потребление: <strong>${p.poe_power_w} W</strong>
                      </div>
                    </div>
                    <button class="btn btn-sm btn-warning-soft"
                      data-poe-mac="${escapeHtml(d.mac)}"
                      data-poe-port="${p.port_idx}"
                      data-poe-name="${escapeHtml(p.name)}">
                      ⚡ PoE Reset
                    </button>
                  </div>
                `
                  )
                  .join("")}
              </div>
            `
              : "";

          return `
            <div class="list-item">
              <div class="list-item-row">
                <div>
                  <div class="item-title">
                    🛸 ${escapeHtml(d.name)}
                    <span class="status-badge ${d.online ? "status-on" : "status-err"}">
                      ${d.online ? "Онлайн" : "Офлайн"}
                    </span>
                  </div>
                  <div class="item-meta">
                    ${escapeHtml(d.model)} • v${escapeHtml(d.version)} • ${escapeHtml(d.ip)}
                  </div>
                </div>
                <div style="display:flex;gap:6px;">
                  ${
                    d.id
                      ? `<button class="btn btn-sm btn-secondary"
                          data-u-led-id="${escapeHtml(d.id)}"
                          data-u-led-mode="${nextLed}"
                          data-u-led-name="${escapeHtml(d.name)}">${ledLabel}</button>`
                      : ""
                  }
                  <button class="btn btn-sm btn-danger-soft"
                    data-u-restart-mac="${escapeHtml(d.mac)}"
                    data-u-restart-name="${escapeHtml(d.name)}">
                    🔄 Ребут
                  </button>
                </div>
              </div>

              <div class="metrics-grid">
                <div class="metric-chip">
                  <span class="metric-chip-label">Uptime</span>
                  <span class="metric-chip-val">${formatUptime(d.uptime_seconds)}</span>
                </div>
                <div class="metric-chip">
                  <span class="metric-chip-label">CPU / RAM</span>
                  <span class="metric-chip-val">${d.cpu_percent || 0}% / ${d.mem_percent || 0}%</span>
                </div>
                <div class="metric-chip">
                  <span class="metric-chip-label">Клиенты</span>
                  <span class="metric-chip-val">${d.num_sta || 0}</span>
                </div>
              </div>
              ${poeHtml}
            </div>
          `;
        })
        .join("");

      devsEl.querySelectorAll("[data-u-led-id]").forEach((btn) => {
        btn.onclick = () =>
          sendServerlessCommand({
            action: "unifi_device_led",
            device_id: btn.dataset.uLedId,
            mode: btn.dataset.uLedMode,
            name: btn.dataset.uLedName,
          });
      });

      devsEl.querySelectorAll("[data-u-restart-mac]").forEach((btn) => {
        btn.onclick = async () => {
          const dname = btn.dataset.uRestartName;
          const ok = await askConfirm(
            `Перезагрузить ${dname}?`,
            `Точка доступа / устройство UniFi «${dname}» будет перезагружено.`
          );
          if (!ok) return;
          sendServerlessCommand({
            action: "unifi_device_restart",
            mac: btn.dataset.uRestartMac,
            name: dname,
          });
        };
      });

      devsEl.querySelectorAll("[data-poe-mac]").forEach((btn) => {
        btn.onclick = async () => {
          const pname = btn.dataset.poeName;
          const ok = await askConfirm(
            `Сбросить питание PoE (${pname})?`,
            `Питание на порту #${btn.dataset.poePort} (${pname}) будет кратковременно отключено и включено заново.`
          );
          if (!ok) return;
          sendServerlessCommand({
            action: "unifi_poe_cycle",
            mac: btn.dataset.poeMac,
            port_idx: Number(btn.dataset.poePort),
            name: pname,
          });
        };
      });
    }
  }

  // ---------------- Render: ADMIN APP ----------------
  function renderAdmin() {
    if (state.user) {
      $("my-uid-text").textContent = state.user.user_id;
      const fullName = [state.user.first_name, state.user.last_name]
        .filter(Boolean)
        .join(" ");
      $("profile-name-subtitle").textContent =
        fullName + (state.user.username ? ` (@${state.user.username})` : "");
    }

    $("users-count-badge").textContent = `${state.adminUsers.length}`;
    const listEl = $("admin-users-list");
    if (!state.adminUsers.length) {
      listEl.innerHTML = `<div class="item-meta">Белый список пуст</div>`;
      return;
    }

    listEl.innerHTML = state.adminUsers
      .map((u) => {
        const isConfigAdmin = u.is_config_admin;
        const badge =
          u.role === "admin"
            ? `<span class="status-badge status-on">Admin</span>`
            : `<span class="status-badge status-neutral">User</span>`;
        const canRemove = u.in_whitelist_file;
        return `
          <div class="list-item">
            <div class="list-item-row">
              <div>
                <div class="item-title">
                  <code>${escapeHtml(u.user_id)}</code>
                  ${badge}
                </div>
                <div class="item-meta">
                  ${isConfigAdmin ? "Задан в settings.yaml (admin_user_ids)" : "Белый список (whitelisted_users.txt)"}
                </div>
              </div>
              ${
                canRemove
                  ? `<button class="btn btn-sm btn-danger-soft" data-remove-uid="${escapeHtml(u.user_id)}">Удалить</button>`
                  : ""
              }
            </div>
          </div>
        `;
      })
      .join("");

    listEl.querySelectorAll("[data-remove-uid]").forEach((btn) => {
      btn.onclick = async () => {
        const uid = btn.dataset.removeUid;
        const ok = await askConfirm(
          "Удалить пользователя?",
          `Пользователь с ID ${uid} потеряет доступ к управлению гостевым Wi-Fi и AdGuard.`
        );
        if (!ok) return;
        if (state.serverless) {
          sendServerlessCommand({ action: "user_remove", user_id: Number(uid) });
          return;
        }
        haptic("medium");
        try {
          const res = await apiCall("/api/admin/users", {
            method: "POST",
            body: { action: "remove", user_id: uid },
          });
          state.adminUsers = res.users || [];
          renderAdmin();
          showToast(res.message || "Пользователь удален");
        } catch (err) {
          showToast(err.message);
        }
      };
    });
  }

  // ---------------- Event Listeners & Init ----------------
  function bindStaticEvents() {
    $("refresh-btn").onclick = () => {
      haptic("light");
      refreshCurrentTab(true);
    };

    $("btn-wifi-all-on").onclick = () => handleWifiToggle("on", "all");
    $("btn-wifi-all-off").onclick = () => handleWifiToggle("off", "all");

    $("btn-ag-on").onclick = () => handleAdguardToggle(true);
    $("btn-adguard-resume-banner").onclick = () => handleAdguardToggle(true);
    document.querySelectorAll("[data-ag-off]").forEach((btn) => {
      btn.onclick = () =>
        handleAdguardToggle(false, Number(btn.dataset.agOff || 10));
    });

    document.querySelectorAll("[data-client-filter]").forEach((btn) => {
      btn.onclick = () => {
        state.clientFilter = btn.dataset.clientFilter;
        document.querySelectorAll("[data-client-filter]").forEach((b) =>
          b.classList.toggle("active", b.dataset.clientFilter === state.clientFilter)
        );
        renderClientsList();
      };
    });

    $("client-search-input").oninput = (e) => {
      state.clientSearch = e.target.value || "";
      renderClientsList();
    };

    const unifiSearchEl = $("unifi-client-search");
    if (unifiSearchEl) {
      unifiSearchEl.oninput = (e) => {
        state.unifiClientSearch = e.target.value || "";
        renderUnifiClientsList();
      };
    }

    $("add-user-form").onsubmit = async (e) => {
      e.preventDefault();
      const input = $("new-user-id-input");
      const uid = input.value.trim();
      if (!uid) return;
      if (state.serverless) {
        sendServerlessCommand({ action: "user_add", user_id: Number(uid) });
        return;
      }
      haptic("medium");
      try {
        const res = await apiCall("/api/admin/users", {
          method: "POST",
          body: { action: "add", user_id: uid },
        });
        input.value = "";
        state.adminUsers = res.users || [];
        renderAdmin();
        haptic("success");
        showToast(res.message || `Пользователь ${uid} добавлен ✅`);
      } catch (err) {
        haptic("error");
        showToast(err.message);
      }
    };

    const copyId = async (idVal) => {
      try {
        await navigator.clipboard.writeText(String(idVal));
        haptic("success");
        showToast(`ID ${idVal} скопирован в буфер обмена 📋`);
      } catch (_) {
        showToast(`Ваш ID: ${idVal}`);
      }
    };

    $("copy-unauth-id-btn").onclick = () => {
      const idText = ($("unauth-user-id").textContent || "").trim();
      if (idText && idText !== "—") {
        copyId(idText);
      } else if (state.user && state.user.user_id) {
        copyId(state.user.user_id);
      }
    };
    $("copy-my-id-btn").onclick = () => {
      if (state.user) copyId(state.user.user_id);
    };

    document.querySelectorAll(".nav-tab").forEach((btn) => {
      btn.onclick = () => {
        haptic("light");
        switchTab(btn.dataset.tab);
      };
    });
  }

  function denyAccess(title, description, tgUserId = null) {
    $("screen-home").hidden = true;
    $("screen-network").hidden = true;
    $("screen-unifi").hidden = true;
    $("screen-admin").hidden = true;
    $("bottom-nav").hidden = true;
    $("refresh-btn").hidden = true;
    $("user-role-pill").hidden = true;

    $("app-icon").textContent = "⛔";
    $("app-title").textContent = "Доступ закрыт";
    $("app-subtitle").textContent = "Требуется авторизация в боте";

    $("unauth-icon").textContent = "🔒";
    $("unauth-title").textContent = title || "Доступ запрещён";
    $("unauth-desc").textContent =
      description ||
      "Это приложение доступно только авторизованным пользователям бота.";

    if (tgUserId) {
      $("unauth-user-id").textContent = tgUserId;
      $("unauth-id-box").hidden = false;
      $("copy-unauth-id-btn").hidden = false;
    } else {
      $("unauth-id-box").hidden = true;
      $("copy-unauth-id-btn").hidden = true;
    }

    $("screen-unauthorized").hidden = false;
  }

  function applyUserRoleAndBoot(initialTab) {
    if (!state.user || !state.user.is_authorized) {
      denyAccess(
        "Вы не добавлены в бот",
        "Ваш аккаунт не находится в белом списке бота. Отправьте ваш Telegram ID администратору для получения доступа:",
        state.user ? state.user.user_id : null
      );
      return;
    }

    $("refresh-btn").hidden = false;
    const rolePill = $("user-role-pill");
    rolePill.hidden = false;
    rolePill.textContent = state.user.role === "admin" ? "Admin" : "User";
    rolePill.classList.toggle("role-admin", state.user.role === "admin");

    if (state.user.is_admin) {
      $("nav-tab-network").hidden = false;
      $("nav-tab-unifi").hidden = !(state.unifi && state.unifi.configured);
      $("nav-tab-admin").hidden = false;
      $("bottom-nav").hidden = false;
    } else {
      $("bottom-nav").hidden = true;
    }

    switchTab(initialTab);
  }

  async function bootstrap() {
    bindStaticEvents();
    $("refresh-btn").hidden = true;
    const initialTab = detectInitialApp();
    const { user: tgUser, isInsideTelegram } = resolveTelegramContext();

    // 1. Check if launched in Serverless Snapshot Mode (?state=... or #state=...)
    const hashToken = extractHashStateToken();
    if (hashToken) {
      try {
        const snapshot = await decodeStateToken(hashToken);
        const snapUser = snapshot && snapshot.user ? snapshot.user : null;
        const resolvedUid = (tgUser && tgUser.id) || (snapUser && snapUser.user_id) || null;

        if (!snapUser || !snapUser.is_authorized) {
          denyAccess(
            "Вы не добавлены в бот",
            "Ваш аккаунт не находится в белом списке бота. Отправьте ваш ID администратору для получения доступа:",
            resolvedUid
          );
          return;
        }

        // Must be opened inside Telegram, and if Telegram provides initDataUnsafe.user (inline button),
        // it must match the user_id in the snapshot
        if (
          !isInsideTelegram ||
          (tgUser && tgUser.id && Number(tgUser.id) !== Number(snapUser.user_id))
        ) {
          denyAccess(
            "Доступ запрещён",
            "Апка может быть открыта только авторизованным пользователем внутри Telegram.",
            tgUser ? tgUser.id : null
          );
          return;
        }

        state.serverless = true;
        state.scopedApp = snapshot.scope || null;
        state.rpc = snapshot.rpc || null;
        state.snapshotTs = snapshot.ts || 0;
        state.botUsername = snapshot.bot_username || "";
        state.user = snapUser;
        state.wifi = snapshot.wifi || null;
        state.adguard = snapshot.adguard || null;
        state.routers = snapshot.routers || [];
        state.clients = snapshot.clients || [];
        state.wolHosts = snapshot.wol_hosts || [];
        state.unifi = snapshot.unifi || null;
        state.adminUsers = snapshot.admin_users || [];
        applyUserRoleAndBoot(initialTab);

        // Automatically sync full live state (and untruncated client lists) in background via RPC
        if (state.rpc && state.rpc.topic && state.rpc.key) {
          executeRpcCommand({ action: "get_state" }, { silent: true });
        }
        return;
      } catch (err) {
        denyAccess(
          "Ошибка доступа",
          "Некорректный или устаревший токен состояния. Отправьте /start боту в чате.",
          tgUser ? tgUser.id : null
        );
        return;
      }
    }

    // 2. Fallback: Local API Mode (only when running local server, not on static GitHub Pages)
    const isStaticHost =
      window.location.hostname.endsWith(".github.io") ||
      window.location.hostname.endsWith(".pages.dev");
    if (!isStaticHost) {
      try {
        const me = await apiCall("/api/me");
        state.user = me.user;
        applyUserRoleAndBoot(initialTab);
        return;
      } catch (_) {}
    }

    // 3. No valid #state token -> Strictly block access
    denyAccess(
      "Доступ закрыт",
      tgUser && tgUser.id
        ? "Вы не авторизованы или открыли апку без токена состояния. Если у вас уже есть доступ — отправьте боту /start и откройте пульт через кнопку в чате. Иначе передайте ваш ID администратору:"
        : "Апка открывается только для авторизованных пользователей через кнопки после команды /start в чате бота. Чтобы узнать свой ID, отправьте боту /get_user_id.",
      tgUser ? tgUser.id : null
    );
  }

  bootstrap();
})();
