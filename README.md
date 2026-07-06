# Secure IoT Gateway

> Đề tài 10: Authenticated IoT Cloud Ingestion

Hệ thống giám sát ra vào IoT (ESP32 + PN532 + HC-SR04) gửi dữ liệu lên Cloud
(Raspberry Pi 5) qua Socket TCP, bảo vệ bằng AES-256-GCM, RSA-1024 (chữ ký số +
trao khoá OAEP) và SHA-512.

## Kiến Trúc

```
[ ESP32: PN532 (NFC) + HC-SR04 (siêu âm) ]
        │  Ký RSA-1024 (SHA-512) + AES-256-GCM + SessionKey (RSA-OAEP)
        ▼
[ Socket TCP qua tên miền ]
        ▼
[ Raspberry Pi 5: Cloud Server ]
    ├── Xác thực chữ ký, chống replay/timestamp bất thường
    ├── Giải mã, kiểm tra toàn vẹn (GCM tag + SHA-512)
    ├── Lưu sensor_data_<device_id>.txt + cloud_transaction.log
    └── Dashboard web đọc log/dữ liệu theo thời gian thực
```

| Thành phần          | Vai trò                                                           |
| --------------------- | ------------------------------------------------------------------ |
| `iot/`              | Firmware ESP32 (PlatformIO, C++/mbedtls)                           |
| `cloud_server/`     | Socket server cho Raspberry Pi 5 (Python)                          |
| `dashboard/`        | Giao diện web giám sát trực quan (Flask)                       |
| `device_simulator/` | Giả lập ESP32 bằng Python — kiểm thử không cần phần cứng |
| `attacker_sim/`     | Kịch bản đối chứng (baseline không bảo mật, MITM)          |
| `tools/`            | Sinh khoá RSA, chuyển PEM → header C, sinh test report          |
| `tests/`            | Kiểm thử tự động + test report                                |
| `docs/`             | Ghi chú thiết kế mật mã                                       |
| `report/`           | Báo cáo bài tập lớn đã biên dịch (PDF)                          |
| `figures/`          | Hình ảnh minh hoạ dùng trong báo cáo                            |

## Cấu Trúc Thư Mục

```
secure-iot-gateway/
├── iot/                    # Firmware ESP32 (PlatformIO)
│   ├── platformio.ini
│   ├── include/            # config.h, sensors.h, crypto_utils.h, device_keys.h
│   └── src/                # main.cpp, sensors.cpp, crypto_utils.cpp
├── cloud_server/           # Cloud Server (Python)
│   ├── server.py
│   ├── crypto_utils.py
│   ├── device_registry.py
│   ├── storage.py
│   └── keys/               # Khoá RSA (sinh bởi tools/generate_keys.py)
├── dashboard/              # Giao diện web (Flask)
├── device_simulator/
├── attacker_sim/
├── tools/
├── data/{samples,logs}/    # Sinh ra khi chạy
├── tests/
├── docs/CRYPTO_NOTES.md
├── report/                 # main.pdf — báo cáo bài tập lớn đã biên dịch
└── figures/                # Hình ảnh minh hoạ dùng trong báo cáo
```

## Cài Đặt

```bash
pip install -r cloud_server/requirements.txt
pip install -r dashboard/requirements.txt
```

## Sinh Khoá RSA

```bash
# Sinh khoá cho Server + thiết bị mặc định "esp32-gate-001"
python tools/generate_keys.py

# Sinh thêm thiết bị khác
python tools/generate_keys.py --device esp32-gate-002 --skip-server
```

Kết quả: `cloud_server/keys/server_private.pem`, `server_public.pem`, và
`cloud_server/keys/devices/<device_id>_{private,public}.pem`. Thiết bị nào KHÔNG
có `_public.pem` tương ứng sẽ bị Cloud Server từ chối ngay ở bước handshake
(`unknown_device`).

## Chạy Cloud Server

```bash
# Chế độ SECURE (mặc định)
python cloud_server/server.py --port 9000

# Chế độ BASELINE — CHỈ dùng để minh hoạ lỗ hổng khi thiếu bảo mật (không xác thực/mã hoá gì cả)
python cloud_server/server.py --baseline --port 9000
```

## Dashboard Giám Sát

```bash
python dashboard/app.py --port 5000
```

Mở `http://127.0.0.1:5000` (hoặc `http://<IP-Pi>:5000`). Hiển thị số liệu
ACK/NACK, tỉ lệ từ chối, thẻ trạng thái theo từng thiết bị, và bảng giao dịch gần
đây — tự làm mới mỗi 3 giây, chỉ đọc dữ liệu từ `data/` nên chạy song song với
Server thoải mái. (Flask dev server — đủ dùng cho LAN/demo cục bộ.)

## Kiểm Thử Không Cần Phần Cứng (`device_simulator`)

```bash
python device_simulator/simulate_device.py --device-id esp32-gate-001 --distance 30 --nfc-uid 04A3B2C1
```

Các cờ hữu ích: `--tamper-cipher` (dữ liệu bị sửa), `--timestamp-offset` (timestamp
bất thường), `--save-packet` / `--replay-file` (tấn công phát lại), `--action download` (tải lại dữ liệu đã upload), `--payload-padding-bytes` (đo hiệu năng với
gói tin lớn hơn). Chi tiết từng tham số: `python device_simulator/simulate_device.py --help`.

Script tấn công đối chứng (Luồng 2 — baseline, Luồng 3 — MITM) nằm ở
`attacker_sim/`; kịch bản quay video theo từng bước được quản lý riêng, không
lặp lại ở đây.

## Kiểm Thử Tự Động

```bash
python tests/test_end_to_end.py            # chạy nhanh, dùng dữ liệu tạm, không ảnh hưởng data/
python tools/generate_test_report.py       # chạy đủ 3 luồng + 6 ca bắt buộc + download,
                                            # ghi kết quả THẬT vào tests/test_report.md
```

## Nạp Firmware Lên ESP32 Thật (`iot/`)

1. Sinh khoá (bước "Sinh Khoá RSA" ở trên), rồi nhúng vào firmware:
   ```bash
   python tools/pem_to_header.py cloud_server/keys/devices/esp32-gate-001_private.pem DEVICE_PRIVATE_KEY_PEM
   python tools/pem_to_header.py cloud_server/keys/server_public.pem SERVER_PUBLIC_KEY_PEM
   ```

   Dán kết quả in ra vào `iot/include/device_keys.h` (đè lên phần placeholder).
2. Sửa `iot/include/config.h`: `WIFI_SSID`, `WIFI_PASSWORD`, `SERVER_HOST`,
   `SERVER_PORT`, và chân cắm HC-SR04/PN532 nếu đấu dây khác mặc định.
3. Build & nạp bằng PlatformIO:
   ```bash
   cd iot
   pio run --target upload
   pio device monitor
   ```

### Đấu Nối Phần Cứng Mặc Định

| Thiết bị   | Chân ESP32                                          |
| ------------ | ---------------------------------------------------- |
| HC-SR04 TRIG | GPIO 5                                               |
| HC-SR04 ECHO | GPIO 18                                              |
| PN532 (I2C)  | SDA=GPIO 21, SCL=GPIO 22, IRQ=GPIO 15, RESET=GPIO 16 |

## Kết Quả Sinh Ra Khi Chạy

- `data/samples/sensor_data_<device_id>.txt` — dữ liệu cảm biến đã giải mã.
- `data/logs/cloud_transaction.log` — log giao dịch (ACK/NACK + lý do + timestamp).

## Lưu Ý Bảo Mật Của Bộ Code Mẫu Này

- Đây là dự án học thuật/demo. Khoá riêng thiết bị nhúng thẳng trong
  `device_keys.h` (thay vì flash mã hoá/secure element) — chấp nhận được cho bài
  tập lớn nhưng KHÔNG dùng cách này cho sản phẩm thật.
- Xem [`docs/CRYPTO_NOTES.md`](docs/CRYPTO_NOTES.md) để hiểu vì sao OAEP dùng
  SHA-256 thay vì SHA-512, và cơ chế hai lớp phòng thủ toàn vẹn (GCM tag + SHA-512).
