"""Quản lý danh sách thiết bị hợp lệ (khoá công khai) và chống tấn công phát lại (replay).

Mỗi thiết bị IoT được đăng ký trước với Cloud bằng cách đặt file
    cloud_server/keys/devices/<device_id>_public.pem
Thiết bị nào không có file public key tương ứng bị coi là KHÔNG hợp lệ (unknown_device).
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from Crypto.PublicKey import RSA

from crypto_utils import load_public_key

# Cho phép lệch thời gian tối đa giữa thiết bị và Server (chống timestamp bất thường).
MAX_TIMESTAMP_SKEW_SECONDS = 30


class DeviceRegistry:
    def __init__(self, devices_dir: Path):
        self.devices_dir = Path(devices_dir)
        self._public_keys: dict[str, RSA.RsaKey] = {}
        self._last_seen_timestamp: dict[str, int] = {}
        self._lock = threading.Lock()
        self.reload()

    def reload(self) -> None:
        keys: dict[str, RSA.RsaKey] = {}
        if self.devices_dir.exists():
            for pem_file in self.devices_dir.glob("*_public.pem"):
                device_id = pem_file.name[: -len("_public.pem")]
                keys[device_id] = load_public_key(pem_file)
        with self._lock:
            self._public_keys = keys

    def is_known(self, device_id: str) -> bool:
        with self._lock:
            return device_id in self._public_keys

    def get_public_key(self, device_id: str) -> RSA.RsaKey | None:
        with self._lock:
            return self._public_keys.get(device_id)

    def check_timestamp(self, device_id: str, timestamp: int) -> tuple[bool, str]:
        """Trả về (hop_le, ly_do_neu_khong_hop_le).

        Phát hiện 2 loại tấn công:
          - replay: timestamp <= timestamp lần gửi gần nhất đã chấp nhận của thiết bị này.
          - timestamp bất thường: lệch quá MAX_TIMESTAMP_SKEW_SECONDS so với giờ Server.
        """
        now = int(time.time())
        if abs(now - timestamp) > MAX_TIMESTAMP_SKEW_SECONDS:
            return False, "timestamp_out_of_range"

        with self._lock:
            last = self._last_seen_timestamp.get(device_id)
            if last is not None and timestamp <= last:
                return False, "replay_detected"

        return True, ""

    def commit_timestamp(self, device_id: str, timestamp: int) -> None:
        with self._lock:
            self._last_seen_timestamp[device_id] = timestamp

    def known_devices(self) -> list[str]:
        with self._lock:
            return sorted(self._public_keys.keys())
