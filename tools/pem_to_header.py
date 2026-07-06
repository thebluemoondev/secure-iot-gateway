#!/usr/bin/env python3
"""Chuyển một file PEM thành khai báo C string để dán vào iot/include/device_keys.h.

Cách dùng:
    python tools/pem_to_header.py cloud_server/keys/devices/esp32-gate-001_private.pem DEVICE_PRIVATE_KEY_PEM
    python tools/pem_to_header.py cloud_server/keys/server_public.pem SERVER_PUBLIC_KEY_PEM

In ra terminal đoạn code C++ (dùng raw string literal R"KEY(...)KEY") — dán đè vào
biến tương ứng trong iot/include/device_keys.h.
"""

import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Cách dùng: python {sys.argv[0]} <duong_dan_file.pem> <TEN_BIEN_C>")
        sys.exit(1)

    pem_path = Path(sys.argv[1])
    var_name = sys.argv[2]

    pem_text = pem_path.read_text().strip()

    print(f'static const char {var_name}[] = R"KEY(')
    print(pem_text)
    print(')KEY";')


if __name__ == "__main__":
    main()
