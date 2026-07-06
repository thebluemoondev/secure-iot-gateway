"""Lưu trữ dữ liệu cảm biến đã giải mã + ghi log giao dịch cloud theo thời gian thực."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

_lock = threading.Lock()


def _timestamp_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def save_sensor_data(data_dir: Path, device_id: str, payload: dict) -> Path:
    """Ghi dữ liệu cảm biến đã giải mã vào data/samples/sensor_data_<device_id>.txt (append)."""
    data_dir.mkdir(parents=True, exist_ok=True)
    out_path = data_dir / f"sensor_data_{device_id}.txt"
    line = f"[{_timestamp_str()}] {json.dumps(payload, ensure_ascii=False)}\n"
    with _lock:
        with out_path.open("a", encoding="utf-8") as f:
            f.write(line)
    return out_path


def log_transaction(log_dir: Path, device_id: str, status: str, reason: str = "",
                     extra: dict | None = None) -> Path:
    """Ghi một dòng vào cloud_transaction.log — dùng cho mục 6 (đánh giá hiệu quả) và demo.

    status: "ACK" | "NACK"
    reason: rỗng nếu ACK; "unknown_device" | "auth" | "integrity" | "replay_detected" |
            "timestamp_out_of_range" nếu NACK.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "cloud_transaction.log"
    record = {
        "time": _timestamp_str(),
        "device_id": device_id,
        "status": status,
        "reason": reason,
    }
    if extra:
        record.update(extra)

    with _lock:
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return log_path
