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

function reasonLabel(reason) {
  if (!reason) return "";
  return REASON_LABELS[reason] || reason;
}

function statusBadge(status, reason) {
  if (status === "ACK") return `<span class="badge ack">ACK</span>`;
  if (status === "NACK") return `<span class="badge nack">NACK · ${reasonLabel(reason)}</span>`;
  return `<span class="badge none">Chưa có dữ liệu</span>`;
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

function renderDevices(devices) {
  const grid = document.getElementById("device-grid");
  if (!devices.length) {
    grid.innerHTML = `<p class="empty-hint">Chưa có thiết bị nào đăng ký. Chạy <code>tools/generate_keys.py</code> trước.</p>`;
    return;
  }

  grid.innerHTML = devices.map((d) => {
    const reading = d.reading;
    let readingHtml = `<p class="empty-hint">Chưa nhận được dữ liệu.</p>`;
    if (reading) {
      const p = reading.payload;
      readingHtml = `
        <div class="reading">
          <div class="reading-row"><span class="k">Khoảng cách</span><span>${p.distance_cm ?? "—"} cm</span></div>
          <div class="reading-row"><span class="k">Có người</span><span>${p.presence ? "Có" : "Không"}</span></div>
          <div class="reading-row"><span class="k">Thẻ NFC</span><span>${p.nfc_detected ? (p.nfc_uid || "—") : "Không quét được"}</span></div>
          <div class="reading-row"><span class="k">Cập nhật lúc</span><span>${reading.time}</span></div>
        </div>
      `;
    }
    return `
      <div class="device-card">
        <div class="device-id">${d.device_id}</div>
        <div class="device-meta">Giao dịch gần nhất: ${d.last_txn_time || "—"}</div>
        <div style="margin-top:10px">${statusBadge(d.last_status, d.last_reason)}</div>
        ${readingHtml}
      </div>
    `;
  }).join("");
}

function renderTransactions(recent) {
  const body = document.getElementById("txn-body");
  if (!recent.length) {
    body.innerHTML = `<tr><td colspan="4" class="empty-hint">Chưa có giao dịch nào.</td></tr>`;
    return;
  }
  body.innerHTML = recent.map((r) => `
    <tr>
      <td>${r.time || "—"}</td>
      <td class="device">${r.device_id || "—"}</td>
      <td>${r.status === "ACK" ? '<span class="badge ack">ACK</span>' : '<span class="badge nack">NACK</span>'}</td>
      <td>${reasonLabel(r.reason)}</td>
    </tr>
  `).join("");
}

async function refresh() {
  try {
    const resp = await fetch("/api/state");
    const state = await resp.json();
    renderStats(state.stats);
    renderDevices(state.devices);
    renderTransactions(state.recent);
    document.getElementById("live-indicator").classList.remove("stale");
  } catch (err) {
    document.getElementById("live-indicator").classList.add("stale");
    console.error("Khong the tai du lieu dashboard:", err);
  }
}

refresh();
setInterval(refresh, 3000);
