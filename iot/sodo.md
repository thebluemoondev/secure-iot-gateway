# Sơ Đồ Đấu Nối — ESP32 + HC-SR04 + PN532

Sơ đồ đấu nối phần cứng cho node ESP32 (board `esp32dev`), theo đúng số chân đã
khai báo trong [`include/config.h`](include/config.h) và cách khởi tạo trong
[`src/sensors.cpp`](src/sensors.cpp).

## Sơ đồ tổng quan

```
                         ┌───────────────────────────┐
                         │         ESP32 DevKit        │
                         │                             │
      HC-SR04            │                             │            PN532 (I2C mode)
   ┌───────────┐         │                             │         ┌───────────────────┐
   │       VCC ├─────────┤ 5V                          │         │ VCC               │
   │       GND ├─────────┤ GND ────────────────────────┼─────────┤ GND                │
   │      TRIG ├─────────┤ GPIO5                        │         │                    │
   │      ECHO ├─────────┤ GPIO18                       │         │                    │
   └───────────┘         │                             │         │                    │
                         │                     GPIO21 ├─────────┤ SDA                │
                         │                     GPIO22 ├─────────┤ SCL                │
                         │                     GPIO15 ├─────────┤ IRQ                │
                         │                     GPIO16 ├─────────┤ RSTPDN (RESET)     │
                         └───────────────────────────┘         └───────────────────┘
```

## Bảng chân cắm

### HC-SR04 (siêu âm — phát hiện có người)

| Chân HC-SR04 | Nối tới ESP32   | Ghi chú                                   |
| ------------- | --------------- | ------------------------------------------ |
| VCC           | 5V              | HC-SR04 cần 5V để đo chính xác             |
| GND           | GND             | Chung GND với toàn bộ mạch                 |
| TRIG          | GPIO 5          | `PIN_ULTRASONIC_TRIG` trong `config.h`     |
| ECHO          | GPIO 18         | `PIN_ULTRASONIC_ECHO` — xem lưu ý dưới     |

> **Lưu ý điện áp ECHO:** chân ECHO của HC-SR04 xuất tín hiệu 5V, trong khi GPIO
> ESP32 chỉ chịu được 3.3V. Nên dùng cầu chia áp điện trở (VD: 1kΩ nối tiếp GND
> qua 2kΩ, lấy điểm giữa vào GPIO18) hoặc module logic level shifter để tránh
> hỏng chân ESP32.

### PN532 (NFC/RFID — chế độ **I2C**, không dùng SPI/HSU)

**Bắt buộc — chỉ 4 chân để chạy được I2C:**

| Chân PN532      | Nối tới ESP32   | Ghi chú                                          |
| ---------------- | --------------- | --------------------------------------------------- |
| VCC              | 3.3V            | Đa số board PN532 hỗ trợ 3.3V; kiểm tra jumper nguồn |
| GND              | GND             | Chung GND với toàn bộ mạch                          |
| SDA              | GPIO 21         | I2C mặc định của ESP32 (`Wire.begin()`)             |
| SCL              | GPIO 22         | I2C mặc định của ESP32 (`Wire.begin()`)             |

**Tùy chọn — không bắt buộc nối dây thật:**

| Chân PN532      | Nối tới ESP32   | Ghi chú                                                  |
| ---------------- | --------------- | ------------------------------------------------------------ |
| IRQ              | GPIO 15         | `PIN_PN532_IRQ` trong `config.h` — chỉ cần nếu dùng chế độ báo ngắt cứng khi có thẻ; `sensors.cpp` hiện đọc thẻ bằng polling (`readPassiveTargetID`), không dùng ngắt, nên có thể để trống chân này trên board |
| RSTPDN (RESET)   | GPIO 16         | `PIN_PN532_RESET` trong `config.h` — nếu không nối, thư viện Adafruit_PN532 tự chuyển sang "soft power down" thay vì "hard power down", vẫn hoạt động bình thường, chỉ mất khả năng reset cứng khi chip bị treo |

> Thư viện `Adafruit_PN532` vẫn yêu cầu 2 tham số IRQ/RESET khi khởi tạo trong
> code (`Adafruit_PN532 nfc(PIN_PN532_IRQ, PIN_PN532_RESET)`), nhưng đó là số
> chân GPIO phía ESP32 để thư viện quản lý nội bộ — không bắt buộc phải nối
> dây vật lý từ 2 chân đó sang board PN532. Nếu muốn tối giản dây nối, chỉ cần
> đấu 4 chân VCC/GND/SDA/SCL và bỏ qua IRQ/RESET.

> **Lưu ý chuyển mạch chế độ:** board PN532 phổ biến (Elechouse/NXP breakout)
> có 2 công tắc gạt (DIP switch) để chọn giao tiếp — phải gạt đúng vị trí
> **I2C** (thường là `1-OFF, 0-ON` hoặc ghi trực tiếp trên board), vì
> `sensors.cpp` khởi tạo qua `Wire` (I2C), không phải SPI hay UART (HSU).

## Nguồn chung

Cả hai module dùng chung **GND** với ESP32. Nếu cấp nguồn HC-SR04 (5V) từ
nguồn ngoài (không qua ESP32), vẫn phải nối chung GND để tín hiệu TRIG/ECHO có
điểm tham chiếu đúng.

## Tài liệu liên quan

- [`include/config.h`](include/config.h) — định nghĩa toàn bộ số chân (`PIN_*`)
- [`src/sensors.cpp`](src/sensors.cpp) — khởi tạo và đọc 2 module
- [`../tailieu/xaydung.md`](../tailieu/xaydung.md) — báo cáo kỹ thuật đầy đủ (kiến trúc, giao thức, phân tích mã nguồn)
