#!/usr/bin/env python3
"""Kiểm thử tự động end-to-end — khởi động Cloud Server thật rồi chạy lần lượt các ca
trong tests/test_report.md bằng device_simulator, kiểm tra phản hồi đúng như kỳ vọng.

Không cần phần cứng ESP32 thật. Dùng khoá test riêng trong tests/_tmp để không đụng
tới data/ và cloud_server/keys dùng cho demo thật.

Cách dùng:
    python tools/generate_keys.py            # nếu chưa sinh khoá lần nào
    python tests/test_end_to_end.py
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable
TEST_PORT = 9500
TMP_DIR = ROOT / "tests" / "_tmp"

passed = 0
failed = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    status = "OK" if condition else "THAT BAI"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not condition else ""))
    if condition:
        passed += 1
    else:
        failed += 1


def wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def run_simulator(*extra_args: str) -> str:
    cmd = [PYTHON, str(ROOT / "device_simulator" / "simulate_device.py"),
           "--port", str(TEST_PORT), *extra_args]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    return result.stdout + result.stderr


def main() -> int:
    if TMP_DIR.exists():
        shutil.rmtree(TMP_DIR)
    (TMP_DIR / "data").mkdir(parents=True)
    (TMP_DIR / "logs").mkdir(parents=True)

    keys_dir = ROOT / "cloud_server" / "keys"
    if not (keys_dir / "server_private.pem").exists() or \
       not (keys_dir / "devices" / "esp32-gate-001_private.pem").exists():
        print("[setup] Chua co khoa test, dang sinh bang tools/generate_keys.py ...")
        subprocess.run([PYTHON, str(ROOT / "tools" / "generate_keys.py"),
                        "--device", "esp32-gate-001"], check=True, cwd=ROOT)

    print(f"[setup] Khoi dong Cloud Server (SECURE) tai port {TEST_PORT} ...")
    server_proc = subprocess.Popen(
        [PYTHON, str(ROOT / "cloud_server" / "server.py"),
         "--port", str(TEST_PORT),
         "--data-dir", str(TMP_DIR / "data"),
         "--log-dir", str(TMP_DIR / "logs")],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    try:
        if not wait_for_port("127.0.0.1", TEST_PORT):
            print("[setup] Server khong khoi dong duoc.")
            return 1

        # --- Ca 1: thiết bị hợp lệ ---
        out = run_simulator("--device-id", "esp32-gate-001", "--distance", "30")
        check("Ca 1 - thiet bi hop le -> ACK", "'status': 'ok'" in out, out)

        # --- Ca 2: thiết bị giả mạo (khoá không đăng ký) ---
        fake_key_dir = TMP_DIR / "fake_key"
        fake_key_dir.mkdir(exist_ok=True)
        subprocess.run(
            [PYTHON, "-c",
             "from Crypto.PublicKey import RSA; "
             f"RSA.generate(1024).export_key().decode() and "
             f"open(r'{fake_key_dir / 'fake_private.pem'}','wb').write(RSA.generate(1024).export_key())"],
            check=True,
        )
        out = run_simulator("--device-id", "esp32-fake-999", "--distance", "30",
                             "--private-key", str(fake_key_dir / "fake_private.pem"))
        check("Ca 2 - thiet bi gia mao -> REJECT unknown_device",
              "unknown_device" in out, out)

        # --- Ca 3: dữ liệu bị sửa trực tiếp (tamper cipher) ---
        out = run_simulator("--device-id", "esp32-gate-001", "--distance", "30", "--tamper-cipher")
        check("Ca 3 - tamper cipher -> NACK integrity", "'reason': 'integrity'" in out, out)

        # --- Ca 4: replay ---
        packet_file = TMP_DIR / "last_packet.json"
        out1 = run_simulator("--device-id", "esp32-gate-001", "--distance", "31",
                              "--save-packet", str(packet_file))
        check("Ca 4a - goi tin dau tien -> ACK", "'status': 'ok'" in out1, out1)

        out2 = run_simulator("--replay-file", str(packet_file))
        check("Ca 4b - phat lai goi tin cu -> NACK replay_detected",
              "replay_detected" in out2, out2)

        # --- Ca 5: timestamp bất thường ---
        out = run_simulator("--device-id", "esp32-gate-001", "--distance", "30",
                             "--timestamp-offset", "999999")
        check("Ca 5 - timestamp bat thuong -> NACK timestamp_out_of_range",
              "timestamp_out_of_range" in out, out)

        # --- Ca 6: log riêng theo từng thiết bị ---
        data_dir = TMP_DIR / "data"
        f1 = data_dir / "sensor_data_esp32-gate-001.txt"
        check("Ca 6 - co file log rieng cho esp32-gate-001", f1.exists())

        log_path = TMP_DIR / "logs" / "cloud_transaction.log"
        check("Cloud_transaction.log duoc ghi", log_path.exists() and log_path.stat().st_size > 0)

    finally:
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()

    print(f"\n=== KET QUA: {passed} OK / {failed} THAT BAI ===")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
