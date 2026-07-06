#!/usr/bin/env python3
"""Luồng 3 — Kẻ tấn công đứng giữa (MITM), bắt gói tin hợp lệ và sửa trường `cipher`.

Đây là một TCP proxy: thiết bị (ESP32 thật hoặc device_simulator) kết nối tới
PROXY thay vì Cloud Server thật. Proxy chuyển tiếp HELLO/READY nguyên vẹn, nhưng
khi thấy gói tin UPLOAD thì SỬA trường `cipher` (giữ nguyên `sig` gốc — vì kẻ tấn
công không có khoá riêng của thiết bị nên không thể ký lại) rồi mới chuyển tiếp
lên Cloud Server thật.

Cách dùng:
    # Cửa sổ 1: Cloud Server thật (chế độ SECURE mặc định), lắng nghe cổng 9000
    python cloud_server/server.py --port 9000

    # Cửa sổ 2: Proxy MITM lắng nghe cổng 9001, chuyển tiếp tới Server thật ở 9000
    python attacker_sim/mitm_tamper.py --listen-port 9001 --target-host 127.0.0.1 --target-port 9000

    # Cửa sổ 3: thiết bị kết nối tới PROXY (9001) thay vì Server thật (9000)
    python device_simulator/simulate_device.py --port 9001 --distance 30

Kỳ vọng: Server thật trả NACK reason=integrity (SHA-512 và/hoặc GCM tag sai lệch),
dù chữ ký RSA (`sig`) vẫn hợp lệ vì kẻ tấn công không đụng vào trường đó.
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
import threading


def recv_line(sock: socket.socket) -> bytes:
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def tamper_packet(raw_line: bytes) -> bytes:
    try:
        packet = json.loads(raw_line.decode("utf-8").strip())
    except json.JSONDecodeError:
        return raw_line

    if packet.get("type") != "UPLOAD" or "cipher" not in packet:
        return raw_line

    cipher_bytes = bytearray(base64.b64decode(packet["cipher"]))
    cipher_bytes[0] ^= 0xFF  # lật 1 byte đầu tiên -> đủ để AES-GCM tag & SHA-512 hash sai lệch
    packet["cipher"] = base64.b64encode(bytes(cipher_bytes)).decode()

    print("[mitm] Da bat goi tin UPLOAD -> SUA truong 'cipher' (giu nguyen 'sig' va 'hash' goc).")
    return (json.dumps(packet, ensure_ascii=False) + "\n").encode("utf-8")


def handle_connection(client_sock: socket.socket, target_host: str, target_port: int) -> None:
    with client_sock, socket.create_connection((target_host, target_port), timeout=5.0) as server_sock:
        # --- Handshake: chuyển tiếp nguyên vẹn ---
        hello = recv_line(client_sock)
        print(f"[mitm] Client -> Server (HELLO): {hello.decode().strip()}")
        server_sock.sendall(hello)

        ready = recv_line(server_sock)
        print(f"[mitm] Server -> Client (READY): {ready.decode().strip()}")
        client_sock.sendall(ready)

        # --- Gói tin nghiệp vụ: bắt và sửa nếu là UPLOAD ---
        upload_line = recv_line(client_sock)
        if not upload_line:
            return
        tampered = tamper_packet(upload_line)
        server_sock.sendall(tampered)

        server_reply = recv_line(server_sock)
        print(f"[mitm] Server -> Client (ACK/NACK): {server_reply.decode().strip()}")
        client_sock.sendall(server_reply)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=9001)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=9000)
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.listen_host, args.listen_port))
        listener.listen(5)
        print(f"[mitm] Proxy dang lang nghe tai {args.listen_host}:{args.listen_port}, "
              f"chuyen tiep toi {args.target_host}:{args.target_port}")

        try:
            while True:
                client_sock, addr = listener.accept()
                print(f"[mitm] Ket noi moi tu {addr}")
                threading.Thread(
                    target=handle_connection,
                    args=(client_sock, args.target_host, args.target_port),
                    daemon=True,
                ).start()
        except KeyboardInterrupt:
            print("\n[mitm] Dung proxy...")


if __name__ == "__main__":
    main()
