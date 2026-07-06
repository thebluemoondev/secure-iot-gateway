#include "sensors.h"
#include "config.h"

#include <Wire.h>
#include <Adafruit_PN532.h>

static Adafruit_PN532 nfc(PIN_PN532_IRQ, PIN_PN532_RESET);
static bool nfcReady = false;

bool sensorsInit() {
    pinMode(PIN_ULTRASONIC_TRIG, OUTPUT);
    pinMode(PIN_ULTRASONIC_ECHO, INPUT);
    digitalWrite(PIN_ULTRASONIC_TRIG, LOW);

    Wire.begin();
    nfc.begin();

    uint32_t versiondata = nfc.getFirmwareVersion();
    if (!versiondata) {
        Serial.println("[sensors] PN532 khong phan hoi. Kiem tra day/dia chi I2C.");
        nfcReady = false;
        return false;
    }

    Serial.printf("[sensors] Tim thay PN532 - firmware ver %d.%d\n",
                  (versiondata >> 16) & 0xFF, (versiondata >> 8) & 0xFF);

    // Cấu hình để đọc thẻ ISO14443A (Mifare/NFC phổ biến)
    nfc.SAMConfig();
    nfcReady = true;
    return true;
}

float readUltrasonicDistanceCm() {
    float total = 0;
    int validSamples = 0;

    for (int i = 0; i < ULTRASONIC_SAMPLE_COUNT; i++) {
        digitalWrite(PIN_ULTRASONIC_TRIG, LOW);
        delayMicroseconds(2);
        digitalWrite(PIN_ULTRASONIC_TRIG, HIGH);
        delayMicroseconds(10);
        digitalWrite(PIN_ULTRASONIC_TRIG, LOW);

        // pulseIn trả về 0 nếu timeout (mặc định 1s) -> coi là không đo được
        unsigned long durationUs = pulseIn(PIN_ULTRASONIC_ECHO, HIGH, 30000UL);
        if (durationUs == 0) {
            continue;
        }

        // v_sound ~ 0.0343 cm/us; chia 2 vì xung đi + về
        float distanceCm = (durationUs * 0.0343f) / 2.0f;
        total += distanceCm;
        validSamples++;
        delay(10);
    }

    if (validSamples == 0) {
        return -1.0f;
    }
    return total / validSamples;
}

bool readNfcUid(uint32_t timeoutMs, String &uidHex) {
    if (!nfcReady) {
        return false;
    }

    uint8_t uid[7];
    uint8_t uidLength;

    bool found = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, timeoutMs);
    if (!found) {
        return false;
    }

    char buf[3];
    uidHex = "";
    for (uint8_t i = 0; i < uidLength; i++) {
        snprintf(buf, sizeof(buf), "%02X", uid[i]);
        uidHex += buf;
    }
    return true;
}

SensorReading takeSensorReading() {
    SensorReading reading{};
    reading.distanceCm = readUltrasonicDistanceCm();
    reading.presenceDetected = (reading.distanceCm > 0 &&
                                 reading.distanceCm < ULTRASONIC_PRESENCE_THRESHOLD_CM);
    reading.nfcDetected = false;
    reading.nfcUidHex = "";

    if (reading.presenceDetected) {
        reading.nfcDetected = readNfcUid(PN532_READ_TIMEOUT_MS, reading.nfcUidHex);
    }

    return reading;
}
