"""Danh sách thẻ NFC được phép ra/vào (whitelist UID).

Đọc từ file JSON:
    cloud_server/keys/authorized_cards.json
    { "authorized_uids": ["04A1B2C3D4", ...] }

Thiết bị quét được thẻ nhưng UID không nằm trong danh sách này -> access_granted = False.
Không quét được thẻ (nfc_detected = False) cũng bị coi là access_granted = False (không có gì để xác minh).
"""

from __future__ import annotations

import json
import threading
from pathlib import Path


class AccessControl:
    def __init__(self, whitelist_path: Path):
        self.whitelist_path = Path(whitelist_path)
        self._authorized_uids: set[str] = set()
        self._lock = threading.Lock()
        self.reload()

    def reload(self) -> None:
        uids: set[str] = set()
        if self.whitelist_path.exists():
            data = json.loads(self.whitelist_path.read_text(encoding="utf-8"))
            uids = {str(u).upper() for u in data.get("authorized_uids", [])}
        with self._lock:
            self._authorized_uids = uids

    def evaluate(self, nfc_detected: bool, nfc_uid: str) -> tuple[bool, str]:
        """Trả về (access_granted, access_reason)."""
        if not nfc_detected or not nfc_uid:
            return False, "no_card"
        with self._lock:
            authorized = nfc_uid.upper() in self._authorized_uids
        return (True, "card_authorized") if authorized else (False, "card_unauthorized")
