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
    const rawHash = window.location.hash.replace(/^#/, "");
    if (!rawHash) return null;
    const params = new URLSearchParams(rawHash);
    return params.get("state");
  }

  // ---------------- Serverless Action Dispatcher ----------------
  function sendServerlessCommand(cmdPayload) {
    const jsonStr = JSON.stringify(cmdPayload);
    // 1. Primary path: Telegram.WebApp.sendData (works when opened from ReplyKeyboardMarkup)
    const isInlineMode = Boolean(tg && tg.initDataUnsafe && tg.initDataUnsafe.query_id);
    if (tg && typeof tg.sendData === "function" && !isInlineMode) {
      haptic("success");
      tg.sendData(jsonStr);
      return true;
    }

    // 2. Fallback path: Deep-link to Bot if opened from an Inline Keyboard button
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

    showToast("Откройте пульт через нижнюю кнопку клавиатуры в чате с ботом для отправки команды.");
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
    const path = window.location.pathname.replace(/^\/+|\/+$/g, "");
    if (["home", "network", "admin"].includes(path)) {
      return path;
    }
    const params = new URLSearchParams(window.location.search);
    const qApp = params.get("app") || params.get("mode") || params.get("tab");
    if (["home", "network", "admin"].includes(qApp)) {
      return qApp;
    }
    const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ""));
    const hApp = hashParams.get("app");
    if (["home", "network", "admin"].includes(hApp)) {
      return hApp;
    }
    const startParam = tg && tg.initDataUnsafe && tg.initDataUnsafe.start_param;
    if (["home", "network", "admin"].includes(startParam)) {
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
    if ((tabName === "network" || tabName === "admin") && !state.user.is_admin) {
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
    const listEl = $("wifi-routers-list");

    const routers = wifi.routers || [];
    const okRouters = routers.filter((r) => r.ok);
    const enabledCount = okRouters.filter((r) => r.enabled).length;

    if (okRouters.length === 0 && routers.length > 0) {
      badge.className = "status-badge status-err";
      badge.textContent = "Ошибка связи";
      sub.textContent = "Роутеры недоступны по RPC";
    } else if (enabledCount > 0) {
      badge.className = "status-badge status-on";
      badge.textContent = "Включен";
      sub.textContent = `Активен на ${enabledCount} из ${routers.length} роутеров`;
    } else {
      badge.className = "status-badge status-off";
      badge.textContent = "Выключен";
      sub.textContent = "Гостевая сеть отключена на всех точках";
    }

    if (wifi.ssids && wifi.ssids.length > 0) {
      ssidsBox.hidden = false;
      ssidsBox.innerHTML = wifi.ssids
        .map((s) => `<span class="ssid-pill">📶 SSID: <strong>${escapeHtml(s)}</strong></span>`)
        .join("");
    } else {
      ssidsBox.hidden = true;
    }

    listEl.innerHTML = routers
      .map((r) => {
        if (!r.ok) {
          return `
            <div class="list-item">
              <div class="list-item-row">
                <div class="item-title">📡 ${escapeHtml(r.name)} <span class="item-meta">(${escapeHtml(r.ip)})</span></div>
                <span class="status-badge status-err">Недоступен</span>
              </div>
              <div class="item-meta">${escapeHtml(r.error || "Ошибка подключения")}</div>
            </div>
          `;
        }
        const ifaces = (r.interfaces || [])
          .map(
            (iface) =>
              `${escapeHtml(iface.section)}: ${iface.enabled ? "🟢 Вкл" : "⚪ Выкл"}`
          )
          .join(" • ");
        const nextAction = r.enabled ? "off" : "on";
        const btnLabel = r.enabled ? "Выключить" : "Включить";
        const btnClass = r.enabled ? "btn-secondary" : "btn-success";

        return `
          <div class="list-item">
            <div class="list-item-row">
              <div>
                <div class="item-title">
                  📡 ${escapeHtml(r.name)}
                  <span class="status-badge ${r.enabled ? "status-on" : "status-off"}">
                    ${r.enabled ? "Вкл" : "Выкл"}
                  </span>
                </div>
                <div class="item-meta">${escapeHtml(r.ip)} ${ifaces ? " • " + ifaces : ""}</div>
              </div>
              <button class="btn btn-sm ${btnClass}" data-router-wifi="${escapeHtml(r.name)}" data-action="${nextAction}">
                ${btnLabel}
              </button>
            </div>
          </div>
        `;
      })
      .join("");

    listEl.querySelectorAll("[data-router-wifi]").forEach((btn) => {
      btn.onclick = () =>
        handleWifiToggle(btn.dataset.action, btn.dataset.routerWifi, btn);
    });
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
    sub.textContent = `Онлайн: ${onlineTotal} • В снимке: ${state.clients.length}`;

    const q = state.clientSearch.trim().toLowerCase();
    const filtered = state.clients.filter((c) => {
      if (state.clientFilter === "online" && !c.online) return false;
      if (!q) return true;
      return (
        (c.hostname || "").toLowerCase().includes(q) ||
        (c.ip || "").toLowerCase().includes(q) ||
        (c.mac || "").toLowerCase().includes(q)
      );
    });

    if (!filtered.length) {
      container.innerHTML = `<div class="item-meta" style="padding: 8px 2px;">Устройства не найдены</div>`;
      return;
    }

    container.innerHTML = filtered
      .map(
        (c) => `
        <div class="client-row">
          <div style="display:flex;align-items:center;gap:9px;min-width:0;">
            <span class="dot ${c.online ? "dot-online" : "dot-offline"}"></span>
            <div style="min-width:0;">
              <div style="font-weight:600;font-size:13.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                ${escapeHtml(c.hostname)}
              </div>
              <div class="item-meta">
                ${escapeHtml(c.ip)} • <code>${escapeHtml(c.mac)}</code>
              </div>
            </div>
          </div>
          <span class="status-badge status-off" style="font-size:11px;">
            ${escapeHtml(c.router || c.interface || "lan")}
          </span>
        </div>
      `
      )
      .join("");
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
    const tgUser = tg && tg.initDataUnsafe && tg.initDataUnsafe.user ? tg.initDataUnsafe.user : null;
    const isInsideTelegram = Boolean(
      (tgUser && tgUser.id) || (tg && tg.platform && tg.platform !== "unknown")
    );

    // 1. Check if launched in Serverless Snapshot Mode (#state=...)
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
        state.snapshotTs = snapshot.ts || 0;
        state.botUsername = snapshot.bot_username || "";
        state.user = snapUser;
        state.wifi = snapshot.wifi || null;
        state.adguard = snapshot.adguard || null;
        state.routers = snapshot.routers || [];
        state.clients = snapshot.clients || [];
        state.wolHosts = snapshot.wol_hosts || [];
        state.adminUsers = snapshot.admin_users || [];
        applyUserRoleAndBoot(initialTab);
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
