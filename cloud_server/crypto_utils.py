"""Thư viện mật mã dùng chung: Cloud Server, device_simulator, attacker_sim.

Thuật toán (khớp với docs/xaydung.md và iot/src/crypto_utils.cpp):
    - Ký số:            RSA-1024 PKCS#1 v1.5 + SHA-512
    - Trao SessionKey:  RSA-1024 OAEP + SHA-256   (xem docs/CRYPTO_NOTES.md)
    - Mã hoá dữ liệu:   AES-256-GCM
    - Toàn vẹn gói tin:  SHA-512(nonce || cipher || tag)
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

AES_SESSION_KEY_BYTES = 32
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16


class IntegrityError(Exception):
    """Toàn vẹn dữ liệu bị vi phạm (hash hoặc GCM tag không khớp)."""


class AuthError(Exception):
    """Chữ ký không hợp lệ hoặc thiết bị không xác định."""


# --- Nạp khoá ----------------------------------------------------------------

def load_private_key(path: Path) -> RSA.RsaKey:
    return RSA.import_key(Path(path).read_bytes())


def load_public_key(path: Path) -> RSA.RsaKey:
    return RSA.import_key(Path(path).read_bytes())


# --- Chữ ký số (RSA-PKCS1v15 + SHA-512) ---------------------------------------

def sign_data(private_key: RSA.RsaKey, data: bytes) -> bytes:
    h = SHA512.new(data)
    return pkcs1_15.new(private_key).sign(h)


def verify_signature(public_key: RSA.RsaKey, data: bytes, signature: bytes) -> bool:
    h = SHA512.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# --- Trao SessionKey (RSA-OAEP + SHA-256) -------------------------------------
# Lưu ý: RSA-1024 + OAEP-SHA512 không khả thi vì độ dài đệm OAEP với SHA-512
# (2*64+2 = 130 byte) vượt quá kích thước modulus (128 byte). Dùng SHA-256 cho
# hàm băm nội bộ của OAEP (đệm 66 byte, dư chỗ cho khoá AES-256 = 32 byte).

def rsa_oaep_encrypt(public_key: RSA.RsaKey, data: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    return cipher.encrypt(data)


def rsa_oaep_decrypt(private_key: RSA.RsaKey, data: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    return cipher.decrypt(data)


# --- AES-256-GCM ---------------------------------------------------------------

def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=AES_GCM_TAG_BYTES)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=AES_GCM_TAG_BYTES)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise IntegrityError(f"AES-GCM tag khong hop le: {exc}") from exc


# --- Toàn vẹn gói tin: SHA-512(nonce || cipher || tag) -------------------------

def integrity_hash(nonce: bytes, ciphertext: bytes, tag: bytes) -> str:
    h = hashlib.sha512()
    h.update(nonce)
    h.update(ciphertext)
    h.update(tag)
    return h.hexdigest()


def verify_integrity_hash(nonce: bytes, ciphertext: bytes, tag: bytes, expected_hex: str) -> bool:
    return integrity_hash(nonce, ciphertext, tag) == expected_hex


# --- Tiện ích ------------------------------------------------------------------

def canonical_metadata(device_id: str, timestamp: int, sensor_type: str) -> bytes:
    """Chuỗi canonical dùng để ký/xác thực metadata — PHẢI khớp iot/src/main.cpp::buildMetadataCanonical."""
    return f"{device_id}|{timestamp}|{sensor_type}".encode("utf-8")
