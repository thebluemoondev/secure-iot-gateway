#!/usr/bin/env python3
"""Dashboard web — hiển thị trực quan dữ liệu IoT + log giao dịch cho video demo.

Đọc trực tiếp từ:
    data/samples/sensor_data_<device_id>.txt   (dữ liệu cảm biến đã giải mã)
    data/logs/cloud_transaction.log             (log ACK/NACK theo thời gian thực)
    cloud_server/keys/devices/*_public.pem      (danh sách thiết bị đã đăng ký)

Không sửa/ghi vào các file trên — chỉ đọc, an toàn khi chạy song song với server.py.

Bình thường KHÔNG cần chạy file này riêng — `cloud_server/server.py` đã tự động
khởi động dashboard này trong 1 luồng nền (trừ khi chạy `server.py --no-dashboard`).
Chỉ chạy riêng file này khi cần dashboard độc lập với socket server.

Cách dùng (độc lập):
    python dashboard/app.py --port 5000
"""

from __future__ import annotations

import argparse
import json
from collections import deque
from pathlib import Path

from flask import Flask, jsonify, render_template

ROOT = Path(__file__).resolve().parent.parent

app = Flask(__name__)

CFG = {
    "data_dir": ROOT / "data" / "samples",
    "log_dir": ROOT / "data" / "logs",
    "devices_dir": ROOT / "cloud_server" / "keys" / "devices",
    "recent_limit": 150,
    "baseline_mode": False,
    # Đối tượng ServerContext thật (chỉ có khi chạy kèm cloud_server/server.py) —
    # cho phép nút "Tắt/Bật mã hoá" lật cờ .baseline ngay lập tức, không cần restart.
    "server_ctx": None,
}


def is_baseline() -> bool:
    ctx = CFG["server_ctx"]
    return ctx.baseline if ctx is not None else CFG["baseline_mode"]


@app.after_request
def _no_cache(response):
    # Tránh Cloudflare/trình duyệt cache JS/CSS cũ trong lúc đang chỉnh sửa dashboard —
    # đã từng gây ra tình trạng bmdev.cloud hiển thị bản giao diện cũ dù Pi5 đã cập nhật.
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


def known_devices() -> list[str]:
    devices_dir = CFG["devices_dir"]
    if not devices_dir.exists():
        return []
    return sorted(p.name[: -len("_public.pem")] for p in devices_dir.glob("*_public.pem"))


def read_last_reading(device_id: str) -> dict | None:
    data_file = CFG["data_dir"] / f"sensor_data_{device_id}.txt"
    if not data_file.exists():
        return None
    with data_file.open("r", encoding="utf-8") as f:
        last_line = deque(f, maxlen=1)
    if not last_line:
        return None
    line = last_line[0].strip()
    if "] " not in line:
        return None
    time_part = line[1:line.index("]")]
    json_part = line.split("] ", 1)[1]
    try:
        payload = json.loads(json_part)
    except json.JSONDecodeError:
        return None
    return {"time": time_part, "payload": payload}


def read_transactions(limit: int) -> list[dict]:
    log_path = CFG["log_dir"] / "cloud_transaction.log"
    if not log_path.exists():
        return []
    with log_path.open("r", encoding="utf-8") as f:
        last_lines = deque(f, maxlen=limit)
    records = []
    for line in last_lines:
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    records.reverse()  # mới nhất trước
    return records


def build_state() -> dict:
    transactions = read_transactions(500)  # đọc rộng để tính thống kê chính xác

    stats = {"ack": 0, "nack": 0, "by_reason": {}}
    last_status_by_device: dict[str, dict] = {}

    for rec in reversed(transactions):  # duyệt cũ -> mới để "last status" là bản ghi mới nhất
        status = rec.get("status")
        device_id = rec.get("device_id", "unknown")
        if status == "ACK":
            stats["ack"] += 1
        elif status == "NACK":
            stats["nack"] += 1
            reason = rec.get("reason", "unknown")
            stats["by_reason"][reason] = stats["by_reason"].get(reason, 0) + 1
        last_status_by_device[device_id] = rec

    devices = []
    for device_id in known_devices():
        reading = read_last_reading(device_id)
        last_txn = last_status_by_device.get(device_id)
        devices.append({
            "device_id": device_id,
            "reading": reading,
            "last_status": last_txn.get("status") if last_txn else None,
            "last_reason": last_txn.get("reason") if last_txn else None,
            "last_txn_time": last_txn.get("time") if last_txn else None,
            "last_access_granted": last_txn.get("access_granted") if last_txn else None,
        })

    return {
        "devices": devices,
        "stats": stats,
        "recent": transactions[: CFG["recent_limit"]],
        "baseline_mode": is_baseline(),
        "mode_toggleable": CFG["server_ctx"] is not None,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/state")
def api_state():
    return jsonify(build_state())


@app.route("/api/mode", methods=["POST"])
def api_toggle_mode():
    """Bật/tắt mã hoá (SECURE <-> baseline) ngay lúc server đang chạy — dùng cho Luồng 2 (demo)."""
    ctx = CFG["server_ctx"]
    if ctx is None:
        return jsonify({"error": "Dashboard dang chay doc lap, khong co server that de doi che do."}), 409
    ctx.baseline = not ctx.baseline
    print(f"[dashboard] Da {'TAT' if ctx.baseline else 'BAT'} ma hoa qua nut tren giao dien web.")
    return jsonify({"baseline_mode": ctx.baseline})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--data-dir", type=Path, default=CFG["data_dir"])
    parser.add_argument("--log-dir", type=Path, default=CFG["log_dir"])
    parser.add_argument("--devices-dir", type=Path, default=CFG["devices_dir"])
    parser.add_argument("--baseline", action="store_true",
                         help="Chi de hien thi dung trang thai - KHONG tu chuyen server sang baseline.")
    args = parser.parse_args()

    CFG["data_dir"] = args.data_dir
    CFG["log_dir"] = args.log_dir
    CFG["devices_dir"] = args.devices_dir
    CFG["baseline_mode"] = args.baseline

    print(f"[dashboard] data_dir={CFG['data_dir']}")
    print(f"[dashboard] log_dir={CFG['log_dir']}")
    print(f"[dashboard] devices_dir={CFG['devices_dir']}")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
