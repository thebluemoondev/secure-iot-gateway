#pragma once

// ============================================================================
// Cấu hình chung cho ESP32 IoT Node
// Đề tài 10 — Authenticated IoT Cloud Ingestion
// ============================================================================

// --- Định danh thiết bị -----------------------------------------------------
// Mỗi node có device_id + cặp khoá riêng (đăng ký trước với Cloud Server).
#define DEVICE_ID "esp32-gate-001"

// --- Wi-Fi -------------------------------------------------------------------
#define WIFI_SSID     "bluemoon"
#define WIFI_PASSWORD "thanhchinh"

// --- Cloud Server (Raspberry Pi 5) -------------------------------------------
// Dùng tên miền thật khi triển khai thực tế (vd: iot.yourdomain.com).
#define SERVER_HOST "iot.yourdomain.com"
#define SERVER_PORT 9000
#define SOCKET_CONNECT_TIMEOUT_MS 5000
#define SOCKET_RESPONSE_TIMEOUT_MS 5000

// --- NTP (đồng bộ thời gian thực để chống replay bằng timestamp) ------------
#define NTP_SERVER_1 "pool.ntp.org"
#define NTP_SERVER_2 "time.google.com"
#define GMT_OFFSET_SEC (7 * 3600)   // UTC+7
#define DAYLIGHT_OFFSET_SEC 0

// --- Chân cắm HC-SR04 (siêu âm) ----------------------------------------------
#define PIN_ULTRASONIC_TRIG 5
#define PIN_ULTRASONIC_ECHO 18
#define ULTRASONIC_PRESENCE_THRESHOLD_CM 50.0f  // < ngưỡng này coi là "có người"
#define ULTRASONIC_SAMPLE_COUNT 3               // lấy trung bình N mẫu để lọc nhiễu

// --- Chân cắm PN532 (NFC/RFID, chế độ I2C) ----------------------------------
#define PIN_PN532_IRQ  (-1)   // khong noi day - chi dung 4 chan I2C (VCC/GND/SDA/SCL)
#define PIN_PN532_RESET (-1)  // khong noi day - xem mach.md muc 3
#define PN532_READ_TIMEOUT_MS 1500  // chờ tối đa khi dò thẻ sau khi phát hiện có người

// --- Chu kỳ đọc cảm biến ------------------------------------------------------
#define SENSOR_POLL_INTERVAL_MS 500
// Chống gửi trùng lặp liên tục khi một người đứng yên trước cửa quá lâu
#define MIN_UPLOAD_INTERVAL_MS 3000

// --- Kích thước khoá / đệm ----------------------------------------------------
#define RSA_KEY_BITS 1024
#define RSA_KEY_BYTES (RSA_KEY_BITS / 8)   // 128 bytes
#define AES_SESSION_KEY_BYTES 32           // AES-256
#define AES_GCM_NONCE_BYTES 12
#define AES_GCM_TAG_BYTES 16
#define SHA512_HASH_BYTES 64

// Lưu ý quan trọng (xem docs/CRYPTO_NOTES.md):
// RSA-OAEP với khoá 1024-bit KHÔNG thể dùng SHA-512 làm hàm băm nội bộ OAEP
// (chiều dài đệm OAEP = 2*hLen+2 = 130 byte > 128 byte của modulus => tràn).
// => OAEP dùng SHA-256 (hLen=32, đệm=66 byte, vẫn còn dư chỗ cho khoá AES-256/32 byte),
// xem crypto_utils.cpp::cryptoInit(). SHA-512 vẫn được dùng cho: (1) chữ ký số
// RSA-PKCS1v15, (2) băm toàn vẹn gói tin.
