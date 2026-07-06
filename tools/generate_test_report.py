#!/usr/bin/env python3
"""Chạy toàn bộ kịch bản bắt buộc (3 luồng đối chứng + 6 ca kiểm thử + download)
và ghi KẾT QUẢ THẬT (log thật, số đo hiệu năng thật) vào tests/test_report.md.

Đây là công cụ để BẠN tự chạy khi sẵn sàng lấy số liệu nộp bài — không tự động
chạy trong quá trình viết code. Mặc định ghi thẳng vào data/samples/ và
data/logs/cloud_transaction.log (giống hệt lúc chạy server.py thật), nên chạy
xong là có ngay dữ liệu mẫu + log thật để nộp kèm báo cáo.

Cách dùng:
    python tools/generate_keys.py                 # nếu chưa sinh khoá
    python tools/generate_test_report.py
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable

SECURE_PORT = 9010
BASELINE_PORT = 9011
MITM_PORT = 9012

DATA_DIR = ROOT / "data" / "samples"
LOG_DIR = ROOT / "data" / "logs"
REPORT_PATH = ROOT / "tests" / "test_report.md"


def wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def run_simulator(*extra_args: str, port: int = SECURE_PORT) -> str:
    cmd = [PYTHON, str(ROOT / "device_simulator" / "simulate_device.py"),
           "--port", str(port), *extra_args]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=20, cwd=ROOT)
    return result.stdout + result.stderr


def extract_response_line(out: str) -> str:
    # Uu tien dong phan hoi UPLOAD/DOWNLOAD (ACK/NACK) vi day la bang chung quan trong nhat;
    # chi roi ve dong Handshake khi ket noi bi tu choi ngay tu buoc do (vd: unknown_device).
    lines = out.splitlines()
    for prefix in ("[simulate] Phan hoi cua Server:", "[simulate] Download",
                   "[simulate] CANH BAO", "[simulate] Handshake:"):
        for line in lines:
            if line.startswith(prefix):
                return line.strip()
    return lines[-1].strip() if lines else "(khong co phan hoi)"


def extract_timing(out: str) -> dict:
    for line in out.splitlines():
        if line.startswith("TIMING:"):
            return json.loads(line[len("TIMING:"):].strip())
    return {}


class Case:
    def __init__(self, number: str, name: str, expect: str):
        self.number = number
        self.name = name
        self.expect = expect
        self.actual = ""
        self.evidence = ""
        self.passed = False


def main() -> None:
    global DATA_DIR, LOG_DIR, REPORT_PATH

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--log-dir", type=Path, default=LOG_DIR)
    parser.add_argument("--report-path", type=Path, default=REPORT_PATH)
    args = parser.parse_args()
    DATA_DIR, LOG_DIR, REPORT_PATH = args.data_dir, args.log_dir, args.report_path
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    if not (ROOT / "cloud_server" / "keys" / "server_private.pem").exists():
        print("[setup] Chua co khoa, dang sinh bang tools/generate_keys.py ...")
        subprocess.run([PYTHON, str(ROOT / "tools" / "generate_keys.py")], check=True, cwd=ROOT)

    cases: list[Case] = []

    print(f"[*] Khoi dong Cloud Server (SECURE) tai port {SECURE_PORT} ...")
    secure_proc = subprocess.Popen(
        [PYTHON, str(ROOT / "cloud_server" / "server.py"), "--port", str(SECURE_PORT),
         "--data-dir", str(DATA_DIR), "--log-dir", str(LOG_DIR)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=ROOT,
    )
    perf_rows = []

    try:
        if not wait_for_port("127.0.0.1", SECURE_PORT):
            print("[fatal] Server SECURE khong khoi dong duoc."); sys.exit(1)

        # --- Ca 1: thiết bị hợp lệ ---
        c = Case("1", "Thiết bị hợp lệ gửi dữ liệu", "ACK")
        out = run_simulator("--device-id", "esp32-gate-001", "--distance", "30")
        c.evidence = extract_response_line(out)
        c.passed = "'status': 'ok'" in out
        c.actual = "✅ ACK" if c.passed else "❌ Không như kỳ vọng"
        cases.append(c)
        perf_small = extract_timing(out)

        # --- Ca 2: thiết bị giả mạo ---
        c = Case("2", "Thiết bị giả mạo gửi dữ liệu", "REJECT unknown_device")
        subprocess.run([PYTHON, "-c",
                         "from Crypto.PublicKey import RSA; "
                         f"open(r'{ROOT / 'tests' / '_fake_private.pem'}','wb').write(RSA.generate(1024).export_key())"],
                        check=True)
        out = run_simulator("--device-id", "esp32-fake-999", "--distance", "30",
                             "--private-key", str(ROOT / "tests" / "_fake_private.pem"))
        (ROOT / "tests" / "_fake_private.pem").unlink(missing_ok=True)
        c.evidence = extract_response_line(out)
        c.passed = "unknown_device" in out
        c.actual = "✅ REJECT unknown_device" if c.passed else "❌ Không như kỳ vọng"
        cases.append(c)

        # --- Ca 3a: tamper cipher trực tiếp ---
        c = Case("3", "Sửa giá trị cảm biến (tamper trực tiếp)", "NACK integrity")
        out = run_simulator("--device-id", "esp32-gate-001", "--distance", "30", "--tamper-cipher")
        c.evidence = extract_response_line(out)
        c.passed = "'reason': 'integrity'" in out
        c.actual = "✅ NACK integrity" if c.passed else "❌ Không như kỳ vọng"
        cases.append(c)

        # --- Ca 3b: MITM ---
        c = Case("3b", "Sửa giá trị cảm biến (MITM giữa đường truyền)", "NACK integrity")
        print(f"[*] Khoi dong MITM proxy tai port {MITM_PORT} -> {SECURE_PORT} ...")
        mitm_proc = subprocess.Popen(
            [PYTHON, str(ROOT / "attacker_sim" / "mitm_tamper.py"),
             "--listen-port", str(MITM_PORT), "--target-port", str(SECURE_PORT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=ROOT,
        )
        wait_for_port("127.0.0.1", MITM_PORT)
        out = run_simulator("--device-id", "esp32-gate-001", "--distance", "30", port=MITM_PORT)
        mitm_proc.terminate()
        c.evidence = extract_response_line(out)
        c.passed = "'reason': 'integrity'" in out
        c.actual = "✅ NACK integrity" if c.passed else "❌ Không như kỳ vọng"
        cases.append(c)

        # --- Ca 4: replay ---
        c = Case("4", "Gửi lại gói tin cũ (replay)", "Lần 1 ACK, lần 2 NACK replay_detected")
        packet_file = ROOT / "tests" / "_last_packet.json"
        out1 = run_simulator("--device-id", "esp32-gate-001", "--distance", "31",
                              "--save-packet", str(packet_file))
        out2 = run_simulator("--replay-file", str(packet_file))
        packet_file.unlink(missing_ok=True)
        ok1 = "'status': 'ok'" in out1
        ok2 = "replay_detected" in out2
        c.evidence = f"{extract_response_line(out1)} | {extract_response_line(out2)}"
        c.passed = ok1 and ok2
        c.actual = "✅ ACK rồi NACK replay_detected" if c.passed else "❌ Không như kỳ vọng"
        cases.append(c)

        # --- Ca 5: timestamp bất thường ---
        c = Case("5", "Timestamp bất thường", "NACK timestamp_out_of_range")
        out = run_simulator("--device-id", "esp32-gate-001", "--distance", "30",
                             "--timestamp-offset", "999999")
        c.evidence = extract_response_line(out)
        c.passed = "timestamp_out_of_range" in out
        c.actual = "✅ NACK timestamp_out_of_range" if c.passed else "❌ Không như kỳ vọng"
        cases.append(c)

        # --- Ca 6: log riêng theo thiết bị ---
        c = Case("6", "Log theo từng thiết bị", "Mỗi thiết bị có file log riêng")
        f1 = DATA_DIR / "sensor_data_esp32-gate-001.txt"
        c.passed = f1.exists()
        c.evidence = str(f1) if f1.exists() else "(khong tim thay file)"
        c.actual = "✅ Có file riêng" if c.passed else "❌ Không tìm thấy"
        cases.append(c)

        # --- Ca 7: baseline (Luồng 2) ---
        c = Case("7", "Baseline không bảo mật (Luồng 2 — đối chứng)",
                  "Server chấp nhận dữ liệu giả, không cảnh báo")
        print(f"[*] Khoi dong Cloud Server (BASELINE) tai port {BASELINE_PORT} ...")
        baseline_proc = subprocess.Popen(
            [PYTHON, str(ROOT / "cloud_server" / "server.py"), "--baseline",
             "--port", str(BASELINE_PORT), "--data-dir", str(DATA_DIR), "--log-dir", str(LOG_DIR)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=ROOT,
        )
        wait_for_port("127.0.0.1", BASELINE_PORT)
        out = subprocess.run(
            [PYTHON, str(ROOT / "attacker_sim" / "baseline_fake_packet.py"), "--port", str(BASELINE_PORT)],
            capture_output=True, text=True, timeout=10, cwd=ROOT,
        ).stdout
        baseline_proc.terminate()
        c.evidence = "Server tra ve ACK cho goi tin plaintext gia mao (xem log 'baseline_no_verification')"
        c.passed = "ACK" in out
        c.actual = "✅ Chấp nhận dữ liệu giả (đúng như minh hoạ lỗ hổng)" if c.passed else "❌ Không như kỳ vọng"
        cases.append(c)

        # --- Download flow (bonus, không có số trong bảng gốc nhưng vẫn kiểm chứng) ---
        out = run_simulator("--device-id", "esp32-gate-001", "--action", "download")
        download_ok = "Download thanh cong" in out
        print(f"[*] Luong Download: {'OK' if download_ok else 'THAT BAI'}")

        # --- Đo hiệu năng: payload lớn hơn ---
        out_large = run_simulator("--device-id", "esp32-gate-001", "--distance", "30",
                                   "--payload-padding-bytes", "4096")
        perf_large = extract_timing(out_large)

        perf_rows = [
            ("Gói nhỏ (~100 byte, JSON cảm biến)", perf_small),
            ("Gói lớn hơn (payload đệm thêm ~4096 byte)", perf_large),
        ]

    finally:
        secure_proc.terminate()
        try:
            secure_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            secure_proc.kill()

    write_report(cases, perf_rows, download_ok)
    print(f"\n[OK] Da ghi ket qua vao {REPORT_PATH}")


def fmt_perf_row(label: str, timing: dict) -> str:
    if not timing:
        return f"| {label} | — | — | — |"
    aes = f"{timing.get('aes_gcm_encrypt_ms', 0):.2f} ms"
    rsa = f"{timing.get('rsa_sign_ms', 0) + timing.get('rsa_oaep_wrap_ms', 0):.2f} ms"
    rtt = f"{timing.get('roundtrip_ms', 0):.2f} ms"
    size = timing.get("payload_bytes", "?")
    return f"| {label} ({size} byte) | {aes} | {rsa} | {rtt} |"


def write_report(cases: list[Case], perf_rows: list[tuple[str, dict]], download_ok: bool) -> None:
    lines = []
    lines.append("# Test Report — Đề Tài 10")
    lines.append("")
    lines.append("> Kết quả dưới đây được sinh **tự động** bởi `tools/generate_test_report.py` "
                  f"vào lúc {time.strftime('%Y-%m-%d %H:%M:%S')}, chạy thật trên "
                  "`cloud_server/server.py` + `device_simulator/` + `attacker_sim/` "
                  "(không phải số liệu giả định). Đối chiếu với "
                  "`../../tailieu/huongdan.md` mục 3.4 và `../../tailieu/xaydung.md` mục 5.")
    lines.append("")
    lines.append("## Bảng Kết Quả")
    lines.append("")
    lines.append("| # | Ca kiểm thử | Kỳ vọng | Kết quả thực tế | Bằng chứng (phản hồi Server) |")
    lines.append("|---|---|---|---|---|")
    for c in cases:
        lines.append(f"| {c.number} | {c.name} | {c.expect} | {c.actual} | `{c.evidence}` |")
    lines.append("")

    lines.append("## Luồng Download (mở rộng — huongdan.md mục 3.3 bước 4)")
    lines.append("")
    status = "✅ Tải lại và giải mã thành công dữ liệu vừa upload" if download_ok else "❌ Thất bại"
    lines.append(f"- Kết quả: {status}")
    lines.append("")

    lines.append("## Đo Hiệu Năng (mục 6 báo cáo — `xaydung.md`)")
    lines.append("")
    lines.append("| Kích thước payload | Thời gian mã hoá AES-GCM | Thời gian ký + bọc SessionKey (RSA, phía thiết bị) | Round-trip tổng |")
    lines.append("|---|---|---|---|")
    for label, timing in perf_rows:
        lines.append(fmt_perf_row(label, timing))
    lines.append("")
    lines.append("> Round-trip tổng đo trên localhost — trên mạng thật qua tên miền sẽ cao hơn "
                  "do độ trễ mạng. Thời gian ký/bọc khoá đo phía thiết bị (client); thời gian "
                  "xác thực/giải mã phía Server không nằm trong số đo này.")
    lines.append("")

    lines.append("## Ghi Chú")
    lines.append("")
    lines.append("- Ca #3 và #3b đều dẫn tới cùng 1 loại lỗi (`integrity`) nhưng theo 2 cơ chế tấn công "
                  "khác nhau (tự sửa vs. chặn giữa đường truyền bằng `attacker_sim/mitm_tamper.py`).")
    lines.append("- Ca #2 bị chặn ngay ở bước **handshake** (trước cả bước ký/mã hoá) vì Server kiểm tra "
                  "`device_id` đã đăng ký chưa.")
    lines.append("- Chạy lại `python tools/generate_test_report.py` bất kỳ lúc nào để làm mới toàn bộ "
                  "bảng kết quả này bằng dữ liệu thật.")
    lines.append("")

    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
