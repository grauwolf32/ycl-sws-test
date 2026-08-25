(() => {
  "use strict";

  const byId = (id) => document.getElementById(id);
  const pretty = (value) => JSON.stringify(value, null, 2);

  function getSessionID() {
    const key = "sws-lab-session-id";
    let value = sessionStorage.getItem(key);
    if (!value) {
      value = typeof crypto.randomUUID === "function"
        ? crypto.randomUUID()
        : `browser-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      sessionStorage.setItem(key, value);
    }
    return value;
  }

  async function request(url, options = {}) {
    const started = performance.now();
    const response = await fetch(url, {
      credentials: "same-origin",
      ...options,
      headers: { "X-Lab-Client": "browser-ui", ...(options.headers || {}) },
    });
    const contentType = response.headers.get("content-type") || "";
    let body = null;
    if (response.status !== 204) {
      body = contentType.includes("application/json")
        ? await response.json()
        : await response.text();
    }
    return {
      ok: response.ok,
      status: response.status,
      origin: response.headers.get("x-lab-response"),
      requestID: response.headers.get("x-request-id"),
      elapsedMS: Math.round(performance.now() - started),
      body,
    };
  }

  function showOriginStatus(result) {
    const element = byId("origin-status");
    element.classList.remove("status-pending", "status-ok", "status-error");
    if (result.ok && result.origin === "origin") {
      element.classList.add("status-ok");
      element.lastElementChild.textContent = "Origin доступен";
    } else {
      element.classList.add("status-error");
      element.lastElementChild.textContent = `Ответ ${result.status}`;
    }
  }

  async function refreshStats() {
    try {
      const result = await request("/api/stats");
      if (!result.ok) return;
      const stats = result.body;
      byId("metric-total").textContent = stats.requests_received.toLocaleString("ru-RU");
      byId("metric-active").textContent = stats.requests_active.toLocaleString("ru-RU");
      byId("metric-browser").textContent = (stats.by_client_type["browser-like"] || 0).toLocaleString("ru-RU");
      byId("metric-client").textContent = (stats.by_client_type["http-client"] || 0).toLocaleString("ru-RU");
    } catch (_) {
      // A blocked stats request is itself useful during an edge-policy test.
    }
  }

  async function refreshInspect() {
    const output = byId("inspect-result");
    output.textContent = "Загрузка…";
    try {
      const result = await request("/api/inspect?source=browser-ui");
      output.textContent = pretty({
        http_status: result.status,
        origin_header: result.origin,
        elapsed_ms: result.elapsedMS,
        response: result.body,
      });
    } catch (error) {
      output.textContent = String(error);
    }
  }

  async function loadBaseline(sessionID) {
    try {
      const health = await request("/healthz");
      showOriginStatus(health);
    } catch (_) {
      showOriginStatus({ ok: false, status: "network error" });
    }

    try {
      const catalog = await request("/api/catalog?page=1&limit=3");
      byId("catalog-state").textContent = catalog.ok ? `${catalog.body.items.length} объекта` : `HTTP ${catalog.status}`;
    } catch (_) {
      byId("catalog-state").textContent = "ошибка сети";
    }

    const event = {
      event: "page_loaded",
      session_id: sessionID,
      viewport: [window.innerWidth, window.innerHeight],
      language_count: navigator.languages ? navigator.languages.length : 0,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      capabilities: {
        cookie: navigator.cookieEnabled,
        webdriver: Boolean(navigator.webdriver),
        touch: navigator.maxTouchPoints > 0,
      },
      sent_at: new Date().toISOString(),
    };

    try {
      const beacon = await request("/api/antibot/beacon", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(event),
      });
      byId("beacon-state").textContent = beacon.status === 204 ? "принят" : `HTTP ${beacon.status}`;
    } catch (_) {
      byId("beacon-state").textContent = "ошибка сети";
    }
  }

  document.querySelectorAll("[data-payload]").forEach((button) => {
    button.addEventListener("click", () => {
      byId("waf-payload").value = button.dataset.payload;
    });
  });

  byId("waf-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const output = byId("waf-result");
    const badge = byId("waf-result-badge");
    const field = byId("waf-field").value.trim() || "comment";
    const form = new URLSearchParams();
    form.set(field, byId("waf-payload").value);
    output.textContent = "Отправка…";
    badge.textContent = "в процессе";

    try {
      const result = await request("/api/waf/form", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form.toString(),
      });
      badge.textContent = result.origin === "origin" ? "origin" : "edge / unknown";
      output.textContent = pretty({
        http_status: result.status,
        origin_header: result.origin,
        request_id: result.requestID,
        elapsed_ms: result.elapsedMS,
        response: result.body,
      });
      await refreshStats();
    } catch (error) {
      badge.textContent = "network error";
      output.textContent = String(error);
    }
  });

  byId("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const output = byId("login-result");
    output.textContent = "Отправка…";
    try {
      const result = await request("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Object.fromEntries(form.entries())),
      });
      output.textContent = `${result.status} · ${result.origin || "edge/unknown"}`;
      await refreshStats();
    } catch (error) {
      output.textContent = String(error);
    }
  });

  byId("delay-button").addEventListener("click", async () => {
    const value = byId("delay-ms").value;
    const output = byId("delay-result");
    output.textContent = "Ожидание…";
    try {
      const result = await request(`/api/slow?ms=${encodeURIComponent(value)}`);
      output.textContent = `${result.status} · ${result.elapsedMS} ms`;
      await refreshStats();
    } catch (error) {
      output.textContent = String(error);
    }
  });

  byId("refresh-inspect").addEventListener("click", refreshInspect);

  const sessionID = getSessionID();
  byId("session-id").textContent = sessionID.slice(0, 13) + "…";
  document.documentElement.dataset.js = "ready";
  loadBaseline(sessionID);
  refreshInspect();
  refreshStats();
  window.setInterval(refreshStats, 5000);
})();
