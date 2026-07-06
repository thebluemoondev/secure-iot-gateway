#pragma once

#include <Arduino.h>

// ============================================================================
// Module cảm biến: HC-SR04 (siêu âm) + PN532 (NFC/RFID)
// ============================================================================

struct SensorReading {
    float distanceCm;       // khoảng cách đo được từ HC-SR04
    bool presenceDetected;   // distanceCm < ULTRASONIC_PRESENCE_THRESHOLD_CM
    bool nfcDetected;        // có thẻ NFC/RFID hợp lệ được quét trong cửa sổ thời gian
    String nfcUidHex;        // UID thẻ (hex), rỗng nếu không quét được thẻ
};

// Khởi tạo chân HC-SR04 và bus/IC PN532. Trả về false nếu PN532 không phản hồi.
bool sensorsInit();

// Đo khoảng cách trung bình (cm) qua ULTRASONIC_SAMPLE_COUNT lần đo HC-SR04.
// Trả về -1.0f nếu cảm biến không phản hồi (timeout echo).
float readUltrasonicDistanceCm();

// Dò thẻ NFC/RFID qua PN532 trong tối đa timeoutMs mili-giây.
// Trả về true và điền uidHex nếu quét được thẻ.
bool readNfcUid(uint32_t timeoutMs, String &uidHex);

// Gộp một lần đọc đầy đủ: đo siêu âm, nếu phát hiện có người thì thử dò thêm NFC.
SensorReading takeSensorReading();
