#include <Arduino.h>
#include <WiFi.h>
#include <time.h>
#include <ArduinoJson.h>

#include "config.h"
#include "device_keys.h"
#include "sensors.h"
#include "crypto_utils.h"

static uint32_t lastUploadMillis = 0;

// ----------------------------------------------------------------------------
static void connectWiFi() {
    Serial.printf("[wifi] Dang ket noi %s ...\n", WIFI_SSID);
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while (WiFi.status() != WL_CONNECTED) {
        delay(300);
        Serial.print(".");
    }
    Serial.printf("\n[wifi] Da ket noi, IP: %s\n", WiFi.localIP().toString().c_str());
}

static void syncTime() {
    // Đồng bộ giờ thực để timestamp gói tin có ý nghĩa (chống replay ở phía Server).
    configTime(GMT_OFFSET_SEC, DAYLIGHT_OFFSET_SEC, NTP_SERVER_1, NTP_SERVER_2);
    Serial.print("[time] Dang dong bo NTP");
    time_t now = time(nullptr);
    while (now < 8 * 3600 * 2) { // chờ tới khi có epoch hợp lệ
        delay(300);
        Serial.print(".");
        now = time(nullptr);
    }
    Serial.printf("\n[time] Epoch hien tai: %ld\n", (long)now);
}

// Đọc một dòng (kết thúc bằng '\n') từ socket, có timeout.
static String readLine(WiFiClient &client, uint32_t timeoutMs) {
    String line;
    uint32_t start = millis();
    while (millis() - start < timeoutMs) {
        while (client.available()) {
            char c = client.read();
            if (c == '\n') return line;
            line += c;
        }
        if (!client.connected()) break;
        delay(5);
    }
    return line;
}

static String buildMetadataCanonical(const String &deviceId, long timestamp, const String &sensorType) {
    // Chuỗi canonical dùng để ký — phía Server phải tái tạo CHÍNH XÁC chuỗi này.
    return deviceId + "|" + String(timestamp) + "|" + sensorType;
}

// ----------------------------------------------------------------------------
static void uploadReading(const SensorReading &reading) {
    WiFiClient client;
    Serial.printf("[net] Ket noi Cloud Server %s:%d ...\n", SERVER_HOST, SERVER_PORT);
    if (!client.connect(SERVER_HOST, SERVER_PORT, SOCKET_CONNECT_TIMEOUT_MS)) {
        Serial.println("[net] Ket noi that bai.");
        return;
    }

    // --- Bước 1: Handshake ---------------------------------------------------
    StaticJsonDocument<128> hello;
    hello["type"] = "HELLO";
    hello["device_id"] = DEVICE_ID;
    String helloStr;
    serializeJson(hello, helloStr);
    client.println(helloStr);

    String helloResp = readLine(client, SOCKET_RESPONSE_TIMEOUT_MS);
    Serial.printf("[net] Server tra loi handshake: %s\n", helloResp.c_str());
    if (helloResp.indexOf("READY") < 0) {
        Serial.println("[net] Server tu choi handshake (thiet bi khong hop le?). Huy.");
        client.stop();
        return;
    }

    // --- Bước 2: Xác thực & trao khoá -----------------------------------------
    long timestamp = time(nullptr);
    const String sensorType = "ultrasonic+nfc";
    String metadataCanonical = buildMetadataCanonical(DEVICE_ID, timestamp, sensorType);

    uint8_t sig[RSA_KEY_BYTES];
    size_t sigLen = 0;
    if (!signWithDeviceKey((const uint8_t *)metadataCanonical.c_str(), metadataCanonical.length(),
                           sig, &sigLen)) {
        Serial.println("[crypto] Ky metadata that bai.");
        client.stop();
        return;
    }

    uint8_t sessionKey[AES_SESSION_KEY_BYTES];
    secureRandomBytes(sessionKey, sizeof(sessionKey));

    uint8_t encSessionKey[RSA_KEY_BYTES];
    size_t encSessionKeyLen = 0;
    if (!wrapSessionKeyForServer(sessionKey, sizeof(sessionKey), encSessionKey, &encSessionKeyLen)) {
        Serial.println("[crypto] Boc SessionKey that bai.");
        client.stop();
        return;
    }

    // --- Bước 3: Mã hoá dữ liệu & kiểm tra toàn vẹn ----------------------------
    StaticJsonDocument<256> payloadDoc;
    payloadDoc["distance_cm"] = reading.distanceCm;
    payloadDoc["presence"] = reading.presenceDetected;
    payloadDoc["nfc_detected"] = reading.nfcDetected;
    payloadDoc["nfc_uid"] = reading.nfcUidHex;
    String payloadStr;
    serializeJson(payloadDoc, payloadStr);

    uint8_t nonce[AES_GCM_NONCE_BYTES];
    secureRandomBytes(nonce, sizeof(nonce));

    size_t ptLen = payloadStr.length();
    uint8_t *cipherBuf = (uint8_t *)malloc(ptLen);
    uint8_t tag[AES_GCM_TAG_BYTES];
    if (!cipherBuf || !aesGcmEncrypt(sessionKey, nonce, (const uint8_t *)payloadStr.c_str(), ptLen,
                                     cipherBuf, tag)) {
        Serial.println("[crypto] Ma hoa AES-GCM that bai.");
        if (cipherBuf) free(cipherBuf);
        client.stop();
        return;
    }

    // hash = SHA-512(nonce || cipher || tag), tính trên byte thô (khong phai base64)
    size_t concatLen = sizeof(nonce) + ptLen + sizeof(tag);
    uint8_t *concatBuf = (uint8_t *)malloc(concatLen);
    memcpy(concatBuf, nonce, sizeof(nonce));
    memcpy(concatBuf + sizeof(nonce), cipherBuf, ptLen);
    memcpy(concatBuf + sizeof(nonce) + ptLen, tag, sizeof(tag));

    uint8_t hashBuf[SHA512_HASH_BYTES];
    sha512Hash(concatBuf, concatLen, hashBuf);
    free(concatBuf);

    // --- Đóng gói JSON hoàn chỉnh ------------------------------------------------
    DynamicJsonDocument packet(2048);
    packet["type"] = "UPLOAD";
    packet["device_id"] = DEVICE_ID;
    packet["timestamp"] = timestamp;

    JsonObject metadata = packet.createNestedObject("metadata");
    metadata["sensor_type"] = sensorType;

    packet["sig"] = base64Encode(sig, sigLen);
    packet["enc_session_key"] = base64Encode(encSessionKey, encSessionKeyLen);
    packet["nonce"] = base64Encode(nonce, sizeof(nonce));
    packet["cipher"] = base64Encode(cipherBuf, ptLen);
    packet["tag"] = base64Encode(tag, sizeof(tag));
    packet["hash"] = toHex(hashBuf, sizeof(hashBuf));

    free(cipherBuf);

    String packetStr;
    serializeJson(packet, packetStr);
    client.println(packetStr);
    Serial.println("[net] Da gui goi tin UPLOAD.");

    String ackResp = readLine(client, SOCKET_RESPONSE_TIMEOUT_MS);
    Serial.printf("[net] Phan hoi tu Cloud Server: %s\n", ackResp.c_str());

    client.stop();
}

// ----------------------------------------------------------------------------
void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n=== ESP32 IoT Node — Đề tài 10 (PN532 + HC-SR04) ===");

    connectWiFi();
    syncTime();

    if (!cryptoInit(DEVICE_PRIVATE_KEY_PEM, SERVER_PUBLIC_KEY_PEM)) {
        Serial.println("[fatal] Khoi tao mat ma that bai. Kiem tra device_keys.h");
        while (true) delay(1000);
    }

    if (!sensorsInit()) {
        Serial.println("[warn] PN532 khong san sang — chi chay duoc cam bien sieu am.");
    }

    Serial.println("[setup] San sang. Bat dau vong lap doc cam bien.");
}

void loop() {
    SensorReading reading = takeSensorReading();

    if (reading.presenceDetected) {
        Serial.printf("[sensor] Phat hien vat can: %.1f cm | NFC: %s\n",
                      reading.distanceCm,
                      reading.nfcDetected ? reading.nfcUidHex.c_str() : "(khong doc duoc the)");

        uint32_t now = millis();
        if (now - lastUploadMillis >= MIN_UPLOAD_INTERVAL_MS) {
            uploadReading(reading);
            lastUploadMillis = now;
        } else {
            Serial.println("[sensor] Bo qua upload (chua du MIN_UPLOAD_INTERVAL_MS).");
        }
    }

    delay(SENSOR_POLL_INTERVAL_MS);
}
