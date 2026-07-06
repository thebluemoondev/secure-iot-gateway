const REASON_LABELS = {
  unknown_device: "Thiết bị lạ",
  auth: "Sai chữ ký",
  integrity: "Dữ liệu bị sửa",
  replay_detected: "Tấn công phát lại",
  timestamp_out_of_range: "Timestamp bất thường",
  malformed_packet: "Gói tin lỗi",
  baseline_no_verification: "Không xác thực (baseline)",
  no_data: "Chưa có dữ liệu",
};

const ACCESS_REASON_LABELS = {
  no_card: "Không quét thẻ",
  card_authorized: "Thẻ hợp lệ",
  card_unauthorized: "Thẻ không hợp lệ",
};

const PRESENCE_GAUGE_MAX_CM = 120; // thang hiển thị thanh đo khoảng cách
const HISTORY_MAX_POINTS = 40;     // số điểm giữ lại cho sparkline mỗi thiết bị
const REFRESH_MS = 1000;           // khớp chu kỳ quét cảm biến mới (1s) phía ESP32

let STATE = { devices: [], stats: { ack: 0, nack: 0, by_reason: {} }, recent: [], baseline_mode: false, mode_toggleable: false };
const DISTANCE_HISTORY = new Map(); // device_id -> [{t, v}]

function reasonLabel(reason) {
  if (!reason) return "";
  return REASON_LABELS[reason] || reason;
}

function statusBadge(status, reason) {
  if (status === "ACK") return `<span class="badge ack">ACK</span>`;
  if (status === "NACK") return `<span class="badge nack">NACK · ${reasonLabel(reason)}</span>`;
  return `<span class="badge none">Chưa có dữ liệu</span>`;
}

function accessBadge(accessGranted) {
  if (accessGranted === true) return `<span class="badge ack">Cho vào</span>`;
  if (accessGranted === false) return `<span class="badge nack">Từ chối</span>`;
  return `<span class="badge none">—</span>`;
}

function renderStats(stats) {
  const total = stats.ack + stats.nack;
  const rate = total > 0 ? Math.round((stats.nack / total) * 100) : 0;
  const el = document.getElementById("stats-row");
  el.innerHTML = `
    <div class="stat-card green">
      <div class="value">${stats.ack}</div>
      <div class="label">Giao dịch ACK</div>
    </div>
    <div class="stat-card red">
      <div class="value">${stats.nack}</div>
      <div class="label">Giao dịch NACK</div>
    </div>
    <div class="stat-card">
      <div class="value">${rate}%</div>
      <div class="label">Tỉ lệ bị từ chối</div>
    </div>
    <div class="stat-card">
      <div class="value">${total}</div>
      <div class="label">Tổng giao dịch</div>
    </div>
  `;
}

function pushHistory(deviceId, distanceCm) {
  if (typeof distanceCm !== "number" || distanceCm < 0) return;
  if (!DISTANCE_HISTORY.has(deviceId)) DISTANCE_HISTORY.set(deviceId, []);
  const arr = DISTANCE_HISTORY.get(deviceId);
  const last = arr[arr.length - 1];
  if (!last || last.v !== distanceCm) {
    arr.push({ t: Date.now(), v: distanceCm });
    while (arr.length > HISTORY_MAX_POINTS) arr.shift();
  }
}

// Sparkline SVG đơn biến (1 series) — không cần chú giải, chỉ nhãn giá trị hiện tại.
function sparkline(deviceId, currentCm) {
  const points = DISTANCE_HISTORY.get(deviceId) || [];
  const w = 100, h = 28, pad = 3;

  if (points.length < 2) {
    return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"></svg>`;
  }

  const values = points.map((p) => p.v);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = Math.max(1, max - min);

  const xy = points.map((p, i) => {
    const x = pad + (i / (points.length - 1)) * (w - pad * 2);
    const y = h - pad - ((p.v - min) / span) * (h - pad * 2);
    return [x, y];
  });

  const linePath = xy.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const areaPath = `${linePath} L${xy[xy.length - 1][0].toFixed(1)},${h - pad} L${xy[0][0].toFixed(1)},${h - pad} Z`;
  const [lastX, lastY] = xy[xy.length - 1];

  return `
    <svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
      <path class="spark-area" d="${areaPath}"></path>
      <path class="spark-line" d="${linePath}"></path>
      <circle class="spark-dot" cx="${lastX.toFixed(1)}" cy="${lastY.toFixed(1)}" r="2.2"></circle>
    </svg>
  `;
}

function presenceGauge(deviceId, distanceCm) {
  const hasReading = typeof distanceCm === "number" && distanceCm >= 0;
  const pct = hasReading ? Math.max(0, Math.min(1, 1 - distanceCm / PRESENCE_GAUGE_MAX_CM)) : 0;
  const level = hasReading && distanceCm < 50 ? "near" : "far";
  return `
    <div class="gauge">
      <div class="gauge-track">
        <div class="gauge-fill ${level}" style="width:${Math.round(pct * 100)}%"></div>
      </div>
      <div class="gauge-value">${hasReading ? distanceCm.toFixed(1) + " cm" : "—"}</div>
    </div>
    <div class="spark-wrap ${level}">${sparkline(deviceId, distanceCm)}</div>
  `;
}

function renderMonitorGrid(devices) {
  const grid = document.getElementById("monitor-grid");
  if (!devices.length) {
    grid.innerHTML = `<p class="empty-hint">Chưa có thiết bị nào đăng ký. Chạy <code>tools/generate_keys.py</code> trước.</p>`;
    return;
  }

  grid.innerHTML = devices.map((d) => {
    const reading = d.reading;
    const p = reading ? reading.payload : null;
    const presenceOn = !!(p && p.presence);
    const nfcOk = !!(p && p.nfc_detected);
    if (p) pushHistory(d.device_id, p.distance_cm);

    return `
      <div class="monitor-card">
        <div class="monitor-card-head">
          <div class="device-id">${d.device_id}</div>
          <span class="presence-dot ${presenceOn ? "on" : "off"}" title="${presenceOn ? "Phát hiện chuyển động" : "Không có chuyển động"}"></span>
        </div>
        <div class="monitor-card-meta">Cập nhật: ${reading ? reading.time : "—"} · Giao dịch gần nhất: ${d.last_txn_time || "—"}</div>

        <div class="monitor-row">
          <span class="k">Khoảng cách</span>
          ${presenceGauge(d.device_id, p ? p.distance_cm : null)}
        </div>

        <div class="monitor-row">
          <span class="k">Thẻ NFC</span>
          <span class="nfc-chip ${nfcOk ? "ok" : "empty"}">${nfcOk ? (p.nfc_uid || "—") : "Chưa quét"}</span>
        </div>

        <div class="monitor-badges">
          ${statusBadge(d.last_status, d.last_reason)}
          ${accessBadge(d.last_access_granted)}
        </div>
      </div>
    `;
  }).join("");
}

function matchesFilter(rec, statusFilter, searchText) {
  if (statusFilter !== "all" && rec.status !== statusFilter) return false;
  if (!searchText) return true;
  const haystack = [
    rec.device_id, rec.reason, rec.nfc_uid, rec.access_reason,
  ].filter(Boolean).join(" ").toLowerCase();
  return haystack.includes(searchText);
}

function txnRow(r) {
  return `
    <tr class="${r.status === 'NACK' ? 'row-nack' : 'row-ack'}">
      <td>${r.time || "—"}</td>
      <td class="device">${r.device_id || "—"}</td>
      <td>${r.status === "ACK" ? '<span class="badge ack">ACK</span>' : '<span class="badge nack">NACK</span>'}</td>
      <td>${reasonLabel(r.reason)}</td>
      <td class="mono">${r.nfc_uid || "—"}</td>
      <td>${accessBadge(r.access_granted)}</td>
    </tr>
  `;
}

function renderTransactions() {
  const statusFilter = document.getElementById("log-filter").value;
  const searchText = document.getElementById("log-search").value.trim().toLowerCase();
  const filtered = STATE.recent.filter((r) => matchesFilter(r, statusFilter, searchText));

  const body = document.getElementById("txn-body");
  body.innerHTML = filtered.length
    ? filtered.map(txnRow).join("")
    : `<tr><td colspan="6" class="empty-hint">Không có giao dịch phù hợp.</td></tr>`;

  document.getElementById("log-count").textContent =
    `Hiển thị ${filtered.length}/${STATE.recent.length} bản ghi gần nhất`;
}

// --- Tab "Kịch bản tấn công" ------------------------------------------------
function renderReasonChips(byReason) {
  const el = document.getElementById("reason-chip-row");
  const entries = Object.entries(byReason || {});
  if (!entries.length) {
    el.innerHTML = `<p class="empty-hint">Chưa có giao dịch NACK nào.</p>`;
    return;
  }
  el.innerHTML = entries
    .sort((a, b) => b[1] - a[1])
    .map(([reason, count]) => `
      <div class="reason-chip">
        <span class="reason-chip-count">${count}</span>
        <span class="reason-chip-label">${reasonLabel(reason)}</span>
      </div>
    `).join("");
}

function isSecurityEvent(r) {
  return r.status === "NACK" || r.access_reason === "card_unauthorized" || r.reason === "baseline_no_verification";
}

function renderAttackLog() {
  const events = STATE.recent.filter(isSecurityEvent);
  const body = document.getElementById("attack-log-body");
  if (!body) return;
  body.innerHTML = events.length
    ? events.map(txnRow).join("")
    : `<tr><td colspan="6" class="empty-hint">Chưa có sự kiện bảo mật nào.</td></tr>`;
}

let MODE_TOGGLE_BUSY = false;

function renderModeBadge(baselineMode, toggleable) {
  document.querySelectorAll(".mode-badge").forEach((el) => {
    const hint = toggleable ? "Bấm để đổi chế độ" : "Chạy dashboard độc lập — không đổi được";
    if (baselineMode) {
      el.className = "mode-badge insecure" + (toggleable ? "" : " disabled");
      el.innerHTML = `<span class="dot"></span> KHÔNG BẢO MẬT (baseline) <small>· ${hint}</small>`;
    } else {
      el.className = "mode-badge secure" + (toggleable ? "" : " disabled");
      el.innerHTML = `<span class="dot"></span> Đang mã hoá (SECURE) <small>· ${hint}</small>`;
    }
  });
}

async function toggleMode() {
  if (MODE_TOGGLE_BUSY || !STATE.mode_toggleable) return;
  MODE_TOGGLE_BUSY = true;
  try {
    const resp = await fetch("/api/mode", { method: "POST" });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      alert(err.error || "Không thể đổi chế độ.");
      return;
    }
    await refresh();
  } catch (err) {
    console.error("Loi khi doi che do:", err);
  } finally {
    MODE_TOGGLE_BUSY = false;
  }
}

function setupTabs() {
  const buttons = document.querySelectorAll(".tab-btn");
  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      buttons.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById("tab-monitor").classList.toggle("hidden", btn.dataset.tab !== "monitor");
      document.getElementById("tab-attack").classList.toggle("hidden", btn.dataset.tab !== "attack");
    });
  });
}

async function refresh() {
  try {
    const resp = await fetch("/api/state");
    STATE = await resp.json();
    renderStats(STATE.stats);
    renderMonitorGrid(STATE.devices);
    renderTransactions();
    renderReasonChips(STATE.stats.by_reason);
    renderAttackLog();
    renderModeBadge(STATE.baseline_mode, STATE.mode_toggleable);
    document.getElementById("live-indicator").classList.remove("stale");
  } catch (err) {
    document.getElementById("live-indicator").classList.add("stale");
    console.error("Khong the tai du lieu dashboard:", err);
  }
}

function setupCopyButtons() {
  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const pre = btn.closest(".code-block")?.querySelector("pre");
      if (!pre) return;
      try {
        await navigator.clipboard.writeText(pre.innerText);
        const original = btn.textContent;
        btn.textContent = "Đã chép!";
        setTimeout(() => { btn.textContent = original; }, 1500);
      } catch (err) {
        console.error("Khong the copy:", err);
      }
    });
  });
}

document.getElementById("log-filter")?.addEventListener("change", renderTransactions);
document.getElementById("log-search")?.addEventListener("input", renderTransactions);
document.querySelectorAll(".mode-badge").forEach((el) => el.addEventListener("click", toggleMode));
setupTabs();
setupCopyButtons();

refresh();
setInterval(refresh, REFRESH_MS);
