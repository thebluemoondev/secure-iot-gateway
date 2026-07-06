// ============================================================================
// ESP32 IoT Node — Đề tài 10 — Authenticated IoT Cloud Ingestion
// Bản sửa đổi tối ưu cấu trúc phân vùng Scope (Biên dịch trực tiếp trên Arduino IDE)
// ============================================================================

#include <Arduino.h>
#include <WiFi.h>
#include <Wire.h>
#include <time.h>
#include <ArduinoJson.h>
#include <Adafruit_PN532.h>

#include <esp_system.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha512.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

// ============================================================================
// ĐƯA TOÀN BỘ MACRO #DEFINE LÊN ĐẦU FILE ĐỂ TRÁNH LỖI SCOPE
// ============================================================================
#define DEVICE_ID "esp32-gate-001"

#define WIFI_SSID     "bmdev"
#define WIFI_PASSWORD ""

#define SERVER_HOST "10.54.93.155"
#define SERVER_PORT 9000
#define SOCKET_CONNECT_TIMEOUT_MS 5000
#define SOCKET_RESPONSE_TIMEOUT_MS 5000

#define NTP_SERVER_1 "pool.ntp.org"
#define NTP_SERVER_2 "time.google.com"
#define GMT_OFFSET_SEC (7 * 3600)   // UTC+7
#define DAYLIGHT_OFFSET_SEC 0

#define PIN_ULTRASONIC_TRIG 5
#define PIN_ULTRASONIC_ECHO 18
#define ULTRASONIC_PRESENCE_THRESHOLD_CM 50.0f
#define ULTRASONIC_SAMPLE_COUNT 3

#define PIN_PN532_IRQ  (-1)
#define PIN_PN532_RESET (-1)
#define PN532_READ_TIMEOUT_MS 1500

#define SENSOR_POLL_INTERVAL_MS 500
#define MIN_UPLOAD_INTERVAL_MS 3000

#define RSA_KEY_BITS 1024
#define RSA_KEY_BYTES (RSA_KEY_BITS / 8)   // 128 bytes
#define AES_SESSION_KEY_BYTES 32           // AES-256
#define AES_GCM_NONCE_BYTES 12
#define AES_GCM_TAG_BYTES 16
#define SHA512_HASH_BYTES 64

// ============================================================================
// ĐỊNH NGHĨA STRUCT & BIẾN TOÀN CỤC HỆ THỐNG
// ============================================================================
static uint32_t lastUploadMillis = 0;

struct SensorReading {
    float distanceCm;
    bool presenceDetected;
    bool nfcDetected;
    String nfcUidHex;
};

// Khai báo tiền trưởng bắt buộc cho các hàm dùng Struct làm tham số/giá trị trả về
SensorReading takeSensorReading();
void uploadReading(const SensorReading &reading);

// ============================================================================
// [device_keys.h]
// ============================================================================
static const char DEVICE_PRIVATE_KEY_PEM[] = R"KEY(
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCZmKJWS+FqbQb0HiuMzlvhhXDyYJa6Lj5AGUl0WD+MIyD/Hrh1
EH5MGxa4DlwU7i3DdAYAl1USo70LXukMhg64InReOREg7iciORKJklm0qr3okK0V
p6OsxKkrF1qNWmN1wM4plVxTuHfxg9ybmVQnpPBfwafQrDK19ndxNVwEBwIDAQAB
AoGAAU4vywX4E3x7u6Vp/1ddpowIyraRcWGlO8w7OJbra1h9Fk3/iVcri6ALUGMm
2zKvBuM8jdK7cV4c5DTZTDbzdw/L5PlC+cYKpvSx2kLG4bNzGoxwQPMptR7Shyf7
ePn1F1GWMOnzzz9GvJ/uFyxaN4zA+nz2JRKWyQowvmlCm1ECQQC8cq8QaZaFHauI
CqaW/DhP2tbNUkoIhlvaIl0YXsepk0u7ROD9/ynNryv8ywFphUGeH9RrdcAvcOFa
T6aNQh2/AkEA0Ke1D9vrYQcqsn9nhLi6P9wtFxf5Y/uie3a6dUXJoSfSYpoPEx/x
zkvN9CBDHinx/WE1awvmyR3sD52iNaa7uQJAR2uXmbrKxyyVg/u1Y2e319vyqOJV
GKIDUcrQSZoyRbyDaTgTpW/9YezP2QD/SgSs98bMdOWtrs0zO00QrFywdQJBAMNK
JEpKoJx407qrSh1LtG6uybkSpEWzMFl0P4IhplziY6QL404YGP7nrkTuqUMjKS3o
/NFLG19jVR0sgbTLcGkCQHpTNjr/jnH+OiJztaG/vw3b4/R/uZuq7ut7bPstCpMD
m7J6QXerr3248kNpu+WuwtYglcxEp+gMqetbAl+Any8=
-----END RSA PRIVATE KEY-----
)KEY";

static const char SERVER_PUBLIC_KEY_PEM[] = R"KEY(
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCaX1908y8zvnKgtIhLk70lqVDM
LYMAOVdrAxB4elSVeYssafBno16e8R6LZkz982R+RvgpV2yAxdXVSAWe7aHwvAQV
OLsjMQtxSlq5AFzEApkA0JGRGpSIwtLgqqlSdmxAU/SrlTgoenRsXo9drGhCOho0
IZf8qUqnNLgv6C6kbQIDAQAB
-----END PUBLIC KEY-----
)KEY";

// ============================================================================
// [crypto_utils] Mật mã tích hợp mbedTLS v2.x
// ============================================================================
static mbedtls_pk_context devicePk;
static mbedtls_pk_context serverPk;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctrDrbg;
static bool cryptoInitialized = false;

static int rngCallback(void *ctx, unsigned char *out, size_t len) {
    return mbedtls_ctr_drbg_random(ctx, out, len);
}

bool cryptoInit(const char *devicePrivateKeyPem, const char *serverPublicKeyPem) {
    mbedtls_pk_init(&devicePk);
    mbedtls_pk_init(&serverPk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctrDrbg);

    const char *pers = "esp32-iot-node";
    int ret = mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        Serial.printf("[crypto] ctr_drbg_seed loi: -0x%04x\n", -ret);
        return false;
    }

    ret = mbedtls_pk_parse_key(&devicePk,
                                (const unsigned char *)devicePrivateKeyPem,
                                strlen(devicePrivateKeyPem) + 1,
                                nullptr, 0);
    if (ret != 0) {
        Serial.printf("[crypto] Parse device private key loi: -0x%04x\n", -ret);
        return false;
    }

    ret = mbedtls_pk_parse_public_key(&serverPk,
                                       (const unsigned char *)serverPublicKeyPem,
                                       strlen(serverPublicKeyPem) + 1);
    if (ret != 0) {
        Serial.printf("[crypto] Parse server public key loi: -0x%04x\n", -ret);
        return false;
    }

    mbedtls_rsa_context *serverRsa = mbedtls_pk_rsa(serverPk);
    if (serverRsa == nullptr) {
        Serial.println("[crypto] Khoa cong khai server khong phai RSA");
        return false;
    }

    mbedtls_rsa_set_padding(serverRsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    cryptoInitialized = true;
    return true;
}

void sha512Hash(const uint8_t *data, size_t len, uint8_t *out64) {
    mbedtls_sha512(data, len, out64, 0);
}

bool signWithDeviceKey(const uint8_t *data, size_t len, uint8_t *sigOut, size_t *sigLen) {
    if (!cryptoInitialized) return false;

    uint8_t digest[SHA512_HASH_BYTES];
    sha512Hash(data, len, digest);

    size_t maxSigLen = RSA_KEY_BYTES;
    int ret = mbedtls_pk_sign(&devicePk, MBEDTLS_MD_SHA512,
                               digest, sizeof(digest),
                               sigOut, &maxSigLen,
                               rngCallback, &ctrDrbg);
    if (ret != 0) {
        Serial.printf("[crypto] pk_sign loi: -0x%04x\n", -ret);
        return false;
    }
    *sigLen = maxSigLen;
    return true;
}

bool wrapSessionKeyForServer(const uint8_t *sessionKey, size_t keyLen,
                             uint8_t *out, size_t *outLen) {
    if (!cryptoInitialized) return false;

    size_t olen = 0;
    int ret = mbedtls_pk_encrypt(&serverPk, sessionKey, keyLen,
                                  out, &olen, RSA_KEY_BYTES,
                                  rngCallback, &ctrDrbg);
    if (ret != 0) {
        Serial.printf("[crypto] OAEP encrypt SessionKey loi: -0x%04x\n", -ret);
        return false;
    }
    *outLen = olen;
    return true;
}

bool aesGcmEncrypt(const uint8_t *key, const uint8_t *nonce,
                    const uint8_t *plaintext, size_t ptLen,
                    uint8_t *cipherOut, uint8_t *tagOut) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, AES_SESSION_KEY_BYTES * 8);
    if (ret != 0) {
        Serial.printf("[crypto] gcm_setkey loi: -0x%04x\n", -ret);
        mbedtls_gcm_free(&gcm);
        return false;
    }

    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, ptLen,
                                     nonce, AES_GCM_NONCE_BYTES,
                                     nullptr, 0,
                                     plaintext, cipherOut,
                                     AES_GCM_TAG_BYTES, tagOut);
    mbedtls_gcm_free(&gcm);

    if (ret != 0) {
        Serial.printf("[crypto] gcm_crypt_and_tag loi: -0x%04x\n", -ret);
        return false;
    }
    return true;
}

void secureRandomBytes(uint8_t *out, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint32_t r = esp_random();
        size_t chunk = (len - i < 4) ? (len - i) : 4;
        memcpy(out + i, &r, chunk);
        i += chunk;
    }
}

String base64Encode(const uint8_t *data, size_t len) {
    size_t outLen = 0;
    mbedtls_base64_encode(nullptr, 0, &outLen, data, len);

    uint8_t *buf = (uint8_t *)malloc(outLen);
    if (!buf) return String();

    size_t written = 0;
    int ret = mbedtls_base64_encode(buf, outLen, &written, data, len);
    String result;
    if (ret == 0) {
        result = String((const char *)buf, written);
    }
    free(buf);
    return result;
}

size_t base64Decode(const String &in, uint8_t *out, size_t outMax) {
    size_t written = 0;
    int ret = mbedtls_base64_decode(out, outMax, &written,
                                     (const unsigned char *)in.c_str(), in.length());
    if (ret != 0) {
        Serial.printf("[crypto] base64_decode loi: -0x%04x\n", -ret);
        return 0;
    }
    return written;
}

String toHex(const uint8_t *data, size_t len) {
    static const char *hexChars = "0123456789abcdef";
    String out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out += hexChars[(data[i] >> 4) & 0x0F];
        out += hexChars[data[i] & 0x0F];
    }
    return out;
}

// ============================================================================
// [sensors] Module cảm biến
// ============================================================================
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

        unsigned long durationUs = pulseIn(PIN_ULTRASONIC_ECHO, HIGH, 30000UL);
        if (durationUs == 0) continue;

        float distanceCm = (durationUs * 0.0343f) / 2.0f;
        total += distanceCm;
        validSamples++;
        delay(10);
    }

    if (validSamples == 0) return -1.0f;
    return total / validSamples;
}

bool readNfcUid(uint32_t timeoutMs, String &uidHex) {
    if (!nfcReady) return false;

    uint8_t uid[7];
    uint8_t uidLength;

    bool found = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, timeoutMs);
    if (!found) return false;

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

// ============================================================================
// [main] Kết nối & Mạng dữ liệu
// ============================================================================
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
    configTime(GMT_OFFSET_SEC, DAYLIGHT_OFFSET_SEC, NTP_SERVER_1, NTP_SERVER_2);
    Serial.print("[time] Dang dong bo NTP");
    time_t now = time(nullptr);
    while (now < 8 * 3600 * 2) {
        delay(300);
        Serial.print(".");
        now = time(nullptr);
    }
    Serial.printf("\n[time] Epoch hien tai: %ld\n", (long)now);
}

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
    return deviceId + "|" + String(timestamp) + "|" + sensorType;
}

void uploadReading(const SensorReading &reading) {
    WiFiClient client;
    Serial.printf("[net] Ket noi Cloud Server %s:%d ...\n", SERVER_HOST, SERVER_PORT);
    if (!client.connect(SERVER_HOST, SERVER_PORT, SOCKET_CONNECT_TIMEOUT_MS)) {
        Serial.println("[net] Ket noi that bai.");
        return;
    }

    // --- Bước 1: Handshake ---
    JsonDocument hello;
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

    // --- Bước 2: Xác thực & trao khoá ---
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

    // --- Bước 3: Mã hoá dữ liệu & kiểm tra toàn vẹn ---
    JsonDocument payloadDoc;
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

    size_t concatLen = sizeof(nonce) + ptLen + sizeof(tag);
    uint8_t *concatBuf = (uint8_t *)malloc(concatLen);
    if (!concatBuf) {
        Serial.println("[sys] Het RAM de tao concatBuf.");
        free(cipherBuf);
        client.stop();
        return;
    }
    memcpy(concatBuf, nonce, sizeof(nonce));
    memcpy(concatBuf + sizeof(nonce), cipherBuf, ptLen);
    memcpy(concatBuf + sizeof(nonce) + ptLen, tag, sizeof(tag));

    uint8_t hashBuf[SHA512_HASH_BYTES];
    sha512Hash(concatBuf, concatLen, hashBuf);
    free(concatBuf);

    // --- Đóng gói JSON hoàn chỉnh ---
    JsonDocument packet;
    packet["type"] = "UPLOAD";
    packet["device_id"] = DEVICE_ID;
    packet["timestamp"] = timestamp;

    JsonObject metadata = packet["metadata"].to<JsonObject>();
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

    JsonDocument ackDoc;
    if (deserializeJson(ackDoc, ackResp) == DeserializationError::Ok && ackDoc["type"] == "ACK") {
        bool accessGranted = ackDoc["access_granted"] | false;
        if (reading.nfcDetected) {
            Serial.println(accessGranted
                ? "[access] THE HOP LE -> CHO VAO."
                : "[access] THE KHONG HOP LE -> TU CHOI.");
        }
    } else {
        Serial.println("[net] Thoi gian cho phan hoi tu server het han hoac goi tin sai format.");
    }

    client.stop();
}

// ============================================================================
// SETUP & LOOP
// ============================================================================
void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n=== ESP32 IoT Node — Đề tài 10 (PN532 + HC-SR04) ===");

    connectWiFi();
    syncTime();

    if (!cryptoInit(DEVICE_PRIVATE_KEY_PEM, SERVER_PUBLIC_KEY_PEM)) {
        Serial.println("[fatal] Khoi tao mat ma that bai.");
        while (true) delay(1000);
    }

    if (!sensorsInit()) {
        Serial.println("[warn] PN532 lỗi hoặc chưa cắm.");
    }

    Serial.println("[setup] San sang đọc cảm biến.");
}

void loop() {
    SensorReading reading = takeSensorReading();

    if (reading.presenceDetected) {
        Serial.printf("[sensor] Khoang cach: %.1f cm | NFC: %s\n",
                      reading.distanceCm,
                      reading.nfcDetected ? reading.nfcUidHex.c_str() : "(khong co the)");

        uint32_t now = millis();
        if (now - lastUploadMillis >= MIN_UPLOAD_INTERVAL_MS) {
            uploadReading(reading);
            lastUploadMillis = now;
        }
    }
    delay(SENSOR_POLL_INTERVAL_MS);
}