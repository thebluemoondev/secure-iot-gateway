#include "crypto_utils.h"
#include "config.h"

#include <esp_system.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha512.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

static mbedtls_pk_context devicePk;   // khoá riêng của thiết bị (ký số)
static mbedtls_pk_context serverPk;   // khoá công khai của Server (bọc SessionKey)
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctrDrbg;
static bool initialized = false;

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

    // Khoá riêng thiết bị: dùng để KÝ (RSA-PKCS1v15 + SHA-512, mặc định của mbedtls_pk)
    ret = mbedtls_pk_parse_key(&devicePk,
                                (const unsigned char *)devicePrivateKeyPem,
                                strlen(devicePrivateKeyPem) + 1,
                                nullptr, 0,
                                rngCallback, &ctrDrbg);
    if (ret != 0) {
        Serial.printf("[crypto] Parse device private key loi: -0x%04x\n", -ret);
        return false;
    }

    // Khoá công khai Server: dùng để BỌC SessionKey (RSA-OAEP + SHA-256)
    ret = mbedtls_pk_parse_public_key(&serverPk,
                                       (const unsigned char *)serverPublicKeyPem,
                                       strlen(serverPublicKeyPem) + 1);
    if (ret != 0) {
        Serial.printf("[crypto] Parse server public key loi: -0x%04x\n", -ret);
        return false;
    }

    // Quan trọng: RSA-1024 + OAEP-SHA512 là KHÔNG THỂ (đệm OAEP 130 byte > modulus 128 byte).
    // Vì vậy tầng bọc SessionKey dùng OAEP với SHA-256 (đệm 66 byte, còn dư chỗ cho khoá 32 byte).
    mbedtls_rsa_context *serverRsa = mbedtls_pk_rsa(serverPk);
    if (serverRsa == nullptr) {
        Serial.println("[crypto] Khoa cong khai server khong phai RSA");
        return false;
    }
    ret = mbedtls_rsa_set_padding(serverRsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    if (ret != 0) {
        Serial.printf("[crypto] set_padding OAEP loi: -0x%04x\n", -ret);
        return false;
    }

    initialized = true;
    return true;
}

bool signWithDeviceKey(const uint8_t *data, size_t len, uint8_t *sigOut, size_t *sigLen) {
    if (!initialized) return false;

    uint8_t digest[SHA512_HASH_BYTES];
    sha512Hash(data, len, digest);

    size_t outLen = 0;
    int ret = mbedtls_pk_sign(&devicePk, MBEDTLS_MD_SHA512,
                               digest, sizeof(digest),
                               sigOut, RSA_KEY_BYTES, &outLen,
                               rngCallback, &ctrDrbg);
    if (ret != 0) {
        Serial.printf("[crypto] pk_sign loi: -0x%04x\n", -ret);
        return false;
    }
    *sigLen = outLen;
    return true;
}

bool wrapSessionKeyForServer(const uint8_t *sessionKey, size_t keyLen,
                             uint8_t *out, size_t *outLen) {
    if (!initialized) return false;

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

void sha512Hash(const uint8_t *data, size_t len, uint8_t *out64) {
    mbedtls_sha512(data, len, out64, 0 /* 0 = SHA-512, 1 = SHA-384 */);
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
