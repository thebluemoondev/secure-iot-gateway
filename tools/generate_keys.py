#!/usr/bin/env python3
"""Sinh cặp khoá RSA-1024 cho Cloud Server và cho từng thiết bị IoT.

Cách dùng:
    python tools/generate_keys.py --device esp32-gate-001
    python tools/generate_keys.py --device esp32-gate-001 --device esp32-gate-002

Kết quả ghi vào:
    cloud_server/keys/server_private.pem
    cloud_server/keys/server_public.pem
    cloud_server/keys/devices/<device_id>_private.pem   (giao cho thiết bị, KHÔNG để trên cloud)
    cloud_server/keys/devices/<device_id>_public.pem     (Cloud Server dùng để xác thực chữ ký)

Sau đó dùng tools/pem_to_header.py để nhúng khoá riêng + khoá công khai server
vào iot/include/device_keys.h cho firmware ESP32.
"""

import argparse
from pathlib import Path

from Crypto.PublicKey import RSA

ROOT = Path(__file__).resolve().parent.parent
KEYS_DIR = ROOT / "cloud_server" / "keys"
DEVICES_DIR = KEYS_DIR / "devices"

RSA_KEY_BITS = 1024  # theo yêu cầu đề bài (huongdan.md mục 3.2) — xem docs/CRYPTO_NOTES.md
                       # về hạn chế của kích thước khoá này.


def generate_keypair() -> RSA.RsaKey:
    return RSA.generate(RSA_KEY_BITS)


def write_keypair(key: RSA.RsaKey, private_path: Path, public_path: Path) -> None:
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(key.export_key("PEM"))
    public_path.write_bytes(key.publickey().export_key("PEM"))
    print(f"  private -> {private_path.relative_to(ROOT)}")
    print(f"  public  -> {public_path.relative_to(ROOT)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--device", action="append", dest="devices", default=[],
        help="device_id cần sinh khoá (có thể lặp lại để sinh nhiều thiết bị)",
    )
    parser.add_argument(
        "--skip-server", action="store_true",
        help="Bỏ qua sinh khoá Server (dùng khi Server đã có khoá từ trước)",
    )
    args = parser.parse_args()

    if not args.devices and not args.skip_server:
        # Mặc định: sinh Server + 1 thiết bị mẫu khớp DEVICE_ID trong iot/include/config.h
        args.devices = ["esp32-gate-001"]

    if not args.skip_server:
        print("[*] Sinh khoá RSA-1024 cho Cloud Server (Raspberry Pi 5)...")
        server_key = generate_keypair()
        write_keypair(server_key, KEYS_DIR / "server_private.pem", KEYS_DIR / "server_public.pem")

    for device_id in args.devices:
        print(f"[*] Sinh khoá RSA-1024 cho thiết bị '{device_id}'...")
        device_key = generate_keypair()
        write_keypair(
            device_key,
            DEVICES_DIR / f"{device_id}_private.pem",
            DEVICES_DIR / f"{device_id}_public.pem",
        )

    print("\n[OK] Hoàn tất. Lưu ý:")
    print("  - Chỉ copy *_private.pem của MỖI thiết bị vào chính thiết bị đó (qua device_keys.h).")
    print("  - Cloud Server chỉ cần giữ server_private.pem + toàn bộ devices/*_public.pem.")
    print("  - KHÔNG commit các file *_private.pem lên git (đã có trong .gitignore).")


if __name__ == "__main__":
    main()
