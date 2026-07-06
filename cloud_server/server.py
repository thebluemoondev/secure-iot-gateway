#!/usr/bin/env python3
"""Cloud Server (giả lập Raspberry Pi 5) — Socket TCP server cho Đề tài 10.

Luồng bảo mật (mặc định, chế độ an toàn):
    HELLO(device_id) -> READY | REJECT(unknown_device)
    UPLOAD{...}       -> kiểm tra timestamp (replay/skew) -> xác thực chữ ký RSA
                         -> kiểm tra SHA-512 toàn vẹn -> giải mã SessionKey (RSA-OAEP)
                         -> giải mã AES-GCM -> lưu file + log -> ACK
                         (bất kỳ bước nào sai -> NACK kèm lý do)
    DOWNLOAD{...}     -> xác thực chữ ký người yêu cầu -> đóng gói lại dữ liệu đã lưu,
                         ký bằng khoá Server, bọc SessionKey mới bằng khoá công khai
                         người yêu cầu -> gửi DOWNLOAD_DATA | NACK

Chế độ baseline (--baseline, CHỈ dùng để demo Luồng 2 - đối chứng KHÔNG bảo mật):
    Bỏ qua toàn bộ xác thực/mã hoá/toàn vẹn — nhận thẳng JSON plaintext và lưu.
    KHÔNG dùng chế độ này ngoài mục đích minh hoạ lỗ hổng trong báo cáo/demo.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socketserver
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import crypto_utils as cu
from device_registry import DeviceRegistry
import storage

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_KEYS_DIR = ROOT / "cloud_server" / "keys"
DEFAULT_DATA_DIR = ROOT / "data" / "samples"
DEFAULT_LOG_DIR = ROOT / "data" / "logs"

SOCKET_TIMEOUT_SECONDS = 15


class ServerContext:
    """Trạng thái dùng chung cho mọi kết nối (nạp 1 lần khi khởi động)."""

    def __init__(self, keys_dir: Path, data_dir: Path, log_dir: Path, baseline: bool):
        self.baseline = baseline
        self.data_dir = data_dir
        self.log_dir = log_dir

        if not baseline:
            self.server_private_key = cu.load_private_key(keys_dir / "server_private.pem")
            self.registry = DeviceRegistry(keys_dir / "devices")
        else:
            self.server_private_key = None
            self.registry = None


CTX: ServerContext | None = None  # gán trong main()


class Handler(socketserver.StreamRequestHandler):
    timeout = SOCKET_TIMEOUT_SECONDS

    def _send_json(self, obj: dict) -> None:
        line = json.dumps(obj, ensure_ascii=False) + "\n"
        self.wfile.write(line.encode("utf-8"))

    def _read_json_line(self) -> dict | None:
        raw = self.rfile.readline()
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8").strip())
        except json.JSONDecodeError:
            return None

    def handle(self) -> None:
        peer = self.client_address
        if CTX.baseline:
            self._handle_baseline(peer)
        else:
            self._handle_secure(peer)

    # --- Chế độ BASELINE (đối chứng, KHÔNG bảo mật — Luồng 2) ------------------
    def _handle_baseline(self, peer) -> None:
        hello = self._read_json_line()
        device_id = (hello or {}).get("device_id", "unknown")
        print(f"[baseline][{peer}] HELLO device_id={device_id!r} (KHONG kiem tra hop le)")
        self._send_json({"type": "READY"})

        packet = self._read_json_line()
        if packet is None:
            return

        print(f"[baseline][{peer}] Nhan goi tin PLAINTEXT: {packet}")
        storage.save_sensor_data(CTX.data_dir, device_id, packet)
        storage.log_transaction(CTX.log_dir, device_id, "ACK", "baseline_no_verification",
                                 extra={"raw_payload": packet})
        self._send_json({"type": "ACK", "status": "ok"})
        print(f"[baseline][{peer}] Da chap nhan du lieu MA KHONG XAC THUC GI (lo hong minh hoa).")

    # --- Chế độ SECURE (mặc định) -----------------------------------------------
    def _handle_secure(self, peer) -> None:
        hello = self._read_json_line()
        if not hello or hello.get("type") != "HELLO":
            self._send_json({"type": "REJECT", "reason": "bad_handshake"})
            return

        device_id = hello.get("device_id", "")
        if not CTX.registry.is_known(device_id):
            print(f"[secure][{peer}] HELLO tu thiet bi LA {device_id!r} -> REJECT unknown_device")
            self._send_json({"type": "REJECT", "reason": "unknown_device"})
            storage.log_transaction(CTX.log_dir, device_id, "NACK", "unknown_device")
            return

        self._send_json({"type": "READY"})

        msg = self._read_json_line()
        if not msg:
            return

        msg_type = msg.get("type")
        if msg_type == "UPLOAD":
            self._handle_upload(device_id, msg)
        elif msg_type == "DOWNLOAD":
            self._handle_download(device_id, msg)
        else:
            self._nack(device_id, "unsupported_type")

    def _nack(self, device_id: str, reason: str) -> None:
        print(f"[secure] NACK device={device_id} reason={reason}")
        self._send_json({"type": "NACK", "reason": reason})
        storage.log_transaction(CTX.log_dir, device_id, "NACK", reason)

    def _handle_upload(self, device_id: str, msg: dict) -> None:
        try:
            timestamp = int(msg["timestamp"])
            sensor_type = msg["metadata"]["sensor_type"]
            sig = base64.b64decode(msg["sig"])
            enc_session_key = base64.b64decode(msg["enc_session_key"])
            nonce = base64.b64decode(msg["nonce"])
            cipher = base64.b64decode(msg["cipher"])
            tag = base64.b64decode(msg["tag"])
            received_hash = msg["hash"]
        except (KeyError, ValueError):
            self._nack(device_id, "malformed_packet")
            return

        # 1) Replay / timestamp bất thường
        ok, reason = CTX.registry.check_timestamp(device_id, timestamp)
        if not ok:
            self._nack(device_id, reason)
            return

        # 2) Xác thực chữ ký (RSA-PKCS1v15 + SHA-512) trên metadata
        pubkey = CTX.registry.get_public_key(device_id)
        metadata_bytes = cu.canonical_metadata(device_id, timestamp, sensor_type)
        if not cu.verify_signature(pubkey, metadata_bytes, sig):
            self._nack(device_id, "auth")
            return

        # 3) Toàn vẹn gói tin: SHA-512(nonce || cipher || tag)
        if not cu.verify_integrity_hash(nonce, cipher, tag, received_hash):
            print(f"[secure] device={device_id}: SHA-512 hash KHONG khop -> du lieu bi can thiep.")
            self._nack(device_id, "integrity")
            return

        # 4) Giải mã SessionKey (RSA-OAEP-SHA256) rồi giải mã AES-GCM
        try:
            session_key = cu.rsa_oaep_decrypt(CTX.server_private_key, enc_session_key)
            plaintext = cu.aes_gcm_decrypt(session_key, nonce, cipher, tag)
        except (cu.IntegrityError, ValueError) as exc:
            print(f"[secure] device={device_id}: AES-GCM tag KHONG hop le ({exc}).")
            self._nack(device_id, "integrity")
            return

        payload = json.loads(plaintext.decode("utf-8"))

        CTX.registry.commit_timestamp(device_id, timestamp)
        storage.save_sensor_data(CTX.data_dir, device_id, payload)
        storage.log_transaction(CTX.log_dir, device_id, "ACK", extra={"sensor_type": sensor_type})

        print(f"[secure] device={device_id}: UPLOAD hop le -> {payload}")
        self._send_json({"type": "ACK", "status": "ok"})

    def _handle_download(self, requester_id: str, msg: dict) -> None:
        try:
            target_device = msg["device_id"]
            timestamp = int(msg["timestamp"])
            sig = base64.b64decode(msg["sig"])
        except (KeyError, ValueError):
            self._nack(requester_id, "malformed_packet")
            return

        ok, reason = CTX.registry.check_timestamp(requester_id, timestamp)
        if not ok:
            self._nack(requester_id, reason)
            return

        pubkey = CTX.registry.get_public_key(requester_id)
        request_bytes = cu.canonical_metadata(requester_id, timestamp, "download")
        if not cu.verify_signature(pubkey, request_bytes, sig):
            self._nack(requester_id, "auth")
            return

        data_file = CTX.data_dir / f"sensor_data_{target_device}.txt"
        if not data_file.exists():
            self._nack(requester_id, "no_data")
            return

        last_line = data_file.read_text(encoding="utf-8").strip().splitlines()[-1]
        json_part = last_line.split("] ", 1)[1] if "] " in last_line else last_line
        payload_bytes = json_part.encode("utf-8")

        # Server đóng vai "người gửi": tạo SessionKey mới, mã hoá lại cho requester.
        session_key = os.urandom(cu.AES_SESSION_KEY_BYTES)
        nonce = os.urandom(cu.AES_GCM_NONCE_BYTES)
        ciphertext, tag = cu.aes_gcm_encrypt(session_key, nonce, payload_bytes)
        packet_hash = cu.integrity_hash(nonce, ciphertext, tag)

        server_metadata = cu.canonical_metadata("cloud-server", timestamp, "download_response")
        server_sig = cu.sign_data(CTX.server_private_key, server_metadata)
        enc_session_key = cu.rsa_oaep_encrypt(pubkey, session_key)

        CTX.registry.commit_timestamp(requester_id, timestamp)
        storage.log_transaction(CTX.log_dir, requester_id, "ACK",
                                 extra={"action": "download", "target_device": target_device})

        self._send_json({
            "type": "DOWNLOAD_DATA",
            "device_id": "cloud-server",
            "timestamp": timestamp,
            "metadata": {"sensor_type": "download_response"},
            "sig": base64.b64encode(server_sig).decode(),
            "enc_session_key": base64.b64encode(enc_session_key).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "cipher": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode(),
            "hash": packet_hash,
        })
        print(f"[secure] requester={requester_id}: DOWNLOAD '{target_device}' -> da gui du lieu.")


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--keys-dir", type=Path, default=DEFAULT_KEYS_DIR)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR)
    parser.add_argument("--baseline", action="store_true",
                         help="CHE DO KHONG BAO MAT — chi dung de demo Luong 2 (doi chung).")
    args = parser.parse_args()

    global CTX
    CTX = ServerContext(args.keys_dir, args.data_dir, args.log_dir, args.baseline)

    mode = "BASELINE (KHONG BAO MAT - chi de demo)" if args.baseline else "SECURE"
    print(f"=== Cloud Server — che do {mode} ===")
    print(f"Lang nghe tai {args.host}:{args.port}")
    if not args.baseline:
        print(f"Thiet bi da dang ky: {CTX.registry.known_devices()}")

    with ThreadingTCPServer((args.host, args.port), Handler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nDang dung server...")


if __name__ == "__main__":
    main()
