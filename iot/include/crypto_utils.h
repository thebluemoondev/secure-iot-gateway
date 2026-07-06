#pragma once

#include <Arduino.h>

// ============================================================================
// Module mật mã cho ESP32 IoT Node (dựa trên mbedtls đi kèm ESP32 Arduino core)
//
// - Ký số:            RSA-1024 PKCS#1 v1.5 + SHA-512  (khoá riêng của thiết bị)
// - Trao SessionKey:  RSA-1024 OAEP + SHA-256          (khoá công khai của Server)
// - Mã hoá dữ liệu:   AES-256-GCM
// - Toàn vẹn gói tin:  SHA-512(nonce || cipher || tag)
//
// Xem docs/CRYPTO_NOTES.md để hiểu vì sao OAEP dùng SHA-256 thay vì SHA-512.
// ============================================================================

// Nạp khoá riêng của thiết bị (PEM) và khoá công khai của Server (PEM).
// Phải gọi trước mọi hàm khác. Trả về false nếu parse khoá thất bại.
bool cryptoInit(const char *devicePrivateKeyPem, const char *serverPublicKeyPem);

// Ký `data` bằng khoá riêng thiết bị. sigOut phải có chỗ chứa >= 128 byte (RSA-1024).
// *sigLen trả về độ dài chữ ký thực tế (128 byte với RSA-1024).
bool signWithDeviceKey(const uint8_t *data, size_t len, uint8_t *sigOut, size_t *sigLen);

// Bọc (mã hoá) session key AES bằng khoá công khai Server (RSA-OAEP-SHA256).
// out phải có chỗ chứa >= 128 byte. *outLen trả về độ dài thực tế.
bool wrapSessionKeyForServer(const uint8_t *sessionKey, size_t keyLen,
                             uint8_t *out, size_t *outLen);

// AES-256-GCM: mã hoá plaintext, sinh cipherOut (cùng độ dài plaintext) và tagOut (16 byte).
bool aesGcmEncrypt(const uint8_t *key, const uint8_t *nonce,
                    const uint8_t *plaintext, size_t ptLen,
                    uint8_t *cipherOut, uint8_t *tagOut);

// Băm SHA-512, out64 phải có chỗ chứa đúng 64 byte.
void sha512Hash(const uint8_t *data, size_t len, uint8_t *out64);

// Sinh `len` byte ngẫu nhiên bằng bộ sinh số cứng của ESP32 (esp_random()).
void secureRandomBytes(uint8_t *out, size_t len);

// Base64 (không xuống dòng), dùng cho các trường nhị phân trong gói JSON.
String base64Encode(const uint8_t *data, size_t len);
size_t base64Decode(const String &in, uint8_t *out, size_t outMax);

// Chuyển chuỗi byte thành hex thường (dùng cho trường "hash").
String toHex(const uint8_t *data, size_t len);
