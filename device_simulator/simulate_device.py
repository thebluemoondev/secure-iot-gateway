#!/usr/bin/env python3
"""Mô phỏng một thiết bị ESP32 (PN532 + HC-SR04) bằng Python.

Dùng để kiểm thử toàn bộ pipeline (handshake -> ký -> mã hoá -> gửi -> ACK/NACK)
trên PC mà KHÔNG cần phần cứng thật — logic mật mã/giao thức giống hệt
iot/src/main.cpp + iot/src/crypto_utils.cpp, chỉ khác ngôn ngữ triển khai.

Ví dụ — Luồng 1 (thiết bị hợp lệ, happy path):
    python device_simulator/simulate_device.py --device-id esp32-gate-001 --distance 30 --nfc-uid 04A3B2C1

Ví dụ — thiết bị giả mạo (khoá không được Server đăng ký):
    python device_simulator/simulate_device.py --device-id esp32-fake-999 --distance 30

Ví dụ — timestamp bất thường:
    python device_simulator/simulate_device.py --device-id esp32-gate-001 --distance 30 --timestamp-offset 999999

Ví dụ — tấn công phát lại (replay): gửi 1 lần, rồi gửi lại y hệt gói tin vừa gửi:
    python device_simulator/simulate_device.py --device-id esp32-gate-001 --distance 30 --save-packet /tmp/p.json
    python device_simulator/simulate_device.py --replay-file /tmp/p.json

Ví dụ — dữ liệu bị sửa trực tiếp trên thiết bị (khác với MITM ở attacker_sim/mitm_tamper.py):
    python device_simulator/simulate_device.py --device-id esp32-gate-001 --distance 30 --tamper-cipher

Ví dụ — download lại dữ liệu vừa upload (đóng vai người nhận):
    python device_simulator/simulate_device.py --device-id esp32-gate-001 --action download

Ví dụ — đo hiệu năng với payload lớn hơn (mục 6 báo cáo):
    python device_simulator/simulate_device.py --device-id esp32-gate-001 --distance 30 --payload-padding-bytes 4096
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "cloud_server"))

import crypto_utils as cu  # noqa: E402

DEFAULT_KEYS_DIR = ROOT / "cloud_server" / "keys"


def read_line(sock: socket.socket, timeout: float = 5.0) -> dict:
    sock.settimeout(timeout)
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return json.loads(buf.decode("utf-8").strip()) if buf.strip() else {}


def send_json(sock: socket.socket, obj: dict) -> None:
    sock.sendall((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))


def build_upload_packet(device_id: str, private_key, server_public_key,
                         distance_cm: float, presence: bool, nfc_uid: str,
                         nfc_detected: bool, timestamp_offset: int,
                         tamper_cipher: bool, payload_padding_bytes: int) -> tuple[dict, dict]:
    """Trả về (packet, timing_ms) — timing_ms phục vụ bảng đo hiệu năng mục 6 báo cáo."""
    timing: dict[str, float] = {}
    timestamp = int(time.time()) + timestamp_offset
    sensor_type = "ultrasonic+nfc"

    metadata_bytes = cu.canonical_metadata(device_id, timestamp, sensor_type)
    t0 = time.perf_counter()
    sig = cu.sign_data(private_key, metadata_bytes)
    timing["rsa_sign_ms"] = (time.perf_counter() - t0) * 1000

    session_key = os.urandom(cu.AES_SESSION_KEY_BYTES)
    t0 = time.perf_counter()
    enc_session_key = cu.rsa_oaep_encrypt(server_public_key, session_key)
    timing["rsa_oaep_wrap_ms"] = (time.perf_counter() - t0) * 1000

    payload = {
        "distance_cm": distance_cm,
        "presence": presence,
        "nfc_detected": nfc_detected,
        "nfc_uid": nfc_uid,
    }
    if payload_padding_bytes > 0:
        # Đệm thêm dữ liệu giả để mô phỏng gói tin lớn hơn (đo hiệu năng theo kích thước).
        payload["padding"] = base64.b64encode(os.urandom(payload_padding_bytes)).decode()
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    timing["payload_bytes"] = len(payload_bytes)

    nonce = os.urandom(cu.AES_GCM_NONCE_BYTES)
    t0 = time.perf_counter()
    ciphertext, tag = cu.aes_gcm_encrypt(session_key, nonce, payload_bytes)
    timing["aes_gcm_encrypt_ms"] = (time.perf_counter() - t0) * 1000

    # hash được tính TRƯỚC khi tamper để mô phỏng đúng kịch bản Luồng 3:
    # kẻ tấn công sửa cipher NHƯNG giữ nguyên hash/sig gốc -> Server phát hiện sai lệch.
    packet_hash = cu.integrity_hash(nonce, ciphertext, tag)

    if tamper_cipher:
        ciphertext = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
        print("[simulate] --tamper-cipher: da sua byte dau tien cua ciphertext "
              "(gia lap du lieu bi can thiep, sig/hash giu nguyen).")

    packet = {
        "type": "UPLOAD",
        "device_id": device_id,
        "timestamp": timestamp,
        "metadata": {"sensor_type": sensor_type},
        "sig": base64.b64encode(sig).decode(),
        "enc_session_key": base64.b64encode(enc_session_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "cipher": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
        "hash": packet_hash,
    }
    return packet, timing


def build_download_request(requester_id: str, target_device: str, private_key,
                            timestamp_offset: int) -> dict:
    timestamp = int(time.time()) + timestamp_offset
    request_bytes = cu.canonical_metadata(requester_id, timestamp, "download")
    sig = cu.sign_data(private_key, request_bytes)
    return {
        "type": "DOWNLOAD",
        "device_id": target_device,
        "timestamp": timestamp,
        "sig": base64.b64encode(sig).decode(),
    }


def process_download_response(resp: dict, requester_private_key, server_public_key) -> None:
    if resp.get("type") != "DOWNLOAD_DATA":
        print(f"[simulate] Download that bai: {resp}")
        return

    nonce = base64.b64decode(resp["nonce"])
    ciphertext = base64.b64decode(resp["cipher"])
    tag = base64.b64decode(resp["tag"])
    sig = base64.b64decode(resp["sig"])
    enc_session_key = base64.b64decode(resp["enc_session_key"])
    timestamp = int(resp["timestamp"])

    server_metadata = cu.canonical_metadata("cloud-server", timestamp, "download_response")
    if not cu.verify_signature(server_public_key, server_metadata, sig):
        print("[simulate] CANH BAO: chu ky cua Server KHONG hop le — tu choi du lieu tai ve.")
        return

    if not cu.verify_integrity_hash(nonce, ciphertext, tag, resp["hash"]):
        print("[simulate] CANH BAO: hash toan ven KHONG khop — tu choi du lieu tai ve.")
        return

    try:
        session_key = cu.rsa_oaep_decrypt(requester_private_key, enc_session_key)
        plaintext = cu.aes_gcm_decrypt(session_key, nonce, ciphertext, tag)
    except (cu.IntegrityError, ValueError) as exc:
        print(f"[simulate] CANH BAO: giai ma that bai ({exc}) — tu choi du lieu tai ve.")
        return

    print(f"[simulate] Download thanh cong. Du lieu goc: {plaintext.decode('utf-8')}")


def run(args: argparse.Namespace) -> None:
    timing: dict = {}

    if args.replay_file:
        packet = json.loads(Path(args.replay_file).read_text(encoding="utf-8"))
        device_id = packet["device_id"]
        private_key = None
        server_public_key = None
        print(f"[simulate] Phat lai (replay) goi tin da luu tu {args.replay_file}")
    else:
        device_id = args.device_id
        private_key_path = args.private_key or (DEFAULT_KEYS_DIR / "devices" / f"{device_id}_private.pem")
        server_public_key_path = args.server_public_key or (DEFAULT_KEYS_DIR / "server_public.pem")

        if not Path(private_key_path).exists():
            print(f"[simulate] LUU Y: khong tim thay khoa rieng '{private_key_path}'.")
            print("           (Neu day la kich ban 'thiet bi gia mao', hay tro --private-key "
                  "toi mot khoa KHONG duoc Server dang ky.)")
            sys.exit(1)

        private_key = cu.load_private_key(Path(private_key_path))
        server_public_key = cu.load_public_key(Path(server_public_key_path))

        if args.action == "download":
            packet = build_download_request(device_id, args.target_device or device_id,
                                             private_key, args.timestamp_offset)
        else:
            packet, timing = build_upload_packet(
                device_id, private_key, server_public_key,
                distance_cm=args.distance, presence=(args.distance < args.presence_threshold),
                nfc_uid=args.nfc_uid, nfc_detected=bool(args.nfc_uid),
                timestamp_offset=args.timestamp_offset, tamper_cipher=args.tamper_cipher,
                payload_padding_bytes=args.payload_padding_bytes,
            )

        if args.save_packet:
            Path(args.save_packet).write_text(json.dumps(packet, ensure_ascii=False, indent=2),
                                                encoding="utf-8")
            print(f"[simulate] Da luu goi tin vao {args.save_packet} (dung cho --replay-file sau).")

    t_roundtrip = time.perf_counter()
    with socket.create_connection((args.host, args.port), timeout=5.0) as sock:
        send_json(sock, {"type": "HELLO", "device_id": device_id})
        hello_resp = read_line(sock)
        print(f"[simulate] Handshake: {hello_resp}")
        if hello_resp.get("type") != "READY":
            print("[simulate] Server tu choi handshake. Dung.")
            return

        send_json(sock, packet)
        print(f"[simulate] Da gui goi tin {packet['type']}.")

        resp = read_line(sock)
        timing["roundtrip_ms"] = (time.perf_counter() - t_roundtrip) * 1000
        print(f"[simulate] Phan hoi cua Server: {resp}")

    if timing:
        print(f"TIMING: {json.dumps(timing)}")

    if args.action == "download" and private_key is not None:
        process_download_response(resp, private_key, server_public_key)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--device-id", default="esp32-gate-001")
    parser.add_argument("--action", choices=["upload", "download"], default="upload")
    parser.add_argument("--target-device", default=None,
                         help="Thiet bi can tai du lieu (mac dinh: chinh device_id nay)")
    parser.add_argument("--private-key", type=Path, default=None,
                         help="Duong dan khoa rieng thay the (de gia lap thiet bi gia mao)")
    parser.add_argument("--server-public-key", type=Path, default=None)
    parser.add_argument("--distance", type=float, default=30.0, help="Khoang cach sieu am (cm)")
    parser.add_argument("--presence-threshold", type=float, default=50.0)
    parser.add_argument("--nfc-uid", default="04A3B2C1", help="UID the NFC (rong = khong quet duoc)")
    parser.add_argument("--timestamp-offset", type=int, default=0,
                         help="Cong them N giay vao timestamp that (mo phong timestamp bat thuong)")
    parser.add_argument("--tamper-cipher", action="store_true",
                         help="Tu sua 1 byte ciphertext truoc khi gui (mo phong du lieu bi sua)")
    parser.add_argument("--payload-padding-bytes", type=int, default=0,
                         help="So byte du lieu gia them vao payload (do hieu nang voi goi tin lon hon)")
    parser.add_argument("--save-packet", type=Path, default=None,
                         help="Luu goi tin JSON da gui ra file (dung lai voi --replay-file)")
    parser.add_argument("--replay-file", type=Path, default=None,
                         help="Gui lai NGUYEN VAN mot goi tin da luu truoc do (mo phong replay attack)")
    args = parser.parse_args()

    run(args)


if __name__ == "__main__":
    main()
