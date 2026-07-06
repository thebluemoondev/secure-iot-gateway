# Ghi Chú Về Lựa Chọn Thuật Toán Mật Mã

## Vì sao OAEP dùng SHA-256 thay vì SHA-512?

Đề bài (`huongdan.md`) yêu cầu: *"RSA 1024-bit (OAEP + SHA-512)"*. Về mặt toán học,
**RSA-1024 kết hợp OAEP với SHA-512 làm hàm băm nội bộ là KHÔNG THỂ THỰC HIỆN ĐƯỢC**:

- Modulus RSA-1024 có kích thước `k = 128 byte`.
- Độ dài đệm tối thiểu của OAEP là `2 * hLen + 2` byte, với `hLen` là kích thước hash.
- Với SHA-512: `hLen = 64` byte → đệm tối thiểu = `2*64+2 = 130 byte`.
- `130 > 128` → **không còn chỗ cho bất kỳ byte dữ liệu nào**, kể cả bản tin rỗng.
  (Thư viện mật mã — PyCryptodome, mbedtls, OpenSSL... — đều báo lỗi kiểu
  `"Plaintext is too long"` / `MBEDTLS_ERR_RSA_BAD_INPUT_DATA` nếu cố dùng tổ hợp này.)

### Giải pháp áp dụng trong dự án này

| Mục đích | Thuật toán | Hàm băm |
|---|---|---|
| Ký số metadata (chống giả mạo danh tính thiết bị) | RSA-1024 PKCS#1 v1.5 | **SHA-512** (đúng yêu cầu đề bài — không có ràng buộc kích thước như OAEP) |
| Bọc AES SessionKey (trao khoá) | RSA-1024 OAEP | **SHA-256** (hLen=32 → đệm 66 byte, còn dư 62 byte cho khoá AES-256 dài 32 byte) |
| Băm toàn vẹn gói tin `SHA-512(nonce‖cipher‖tag)` | — | **SHA-512** (đúng yêu cầu đề bài — không liên quan RSA/OAEP) |

→ Vẫn giữ đúng tinh thần "SHA-512 xuyên suốt hệ thống" như đề bài, chỉ thay đổi
hàm băm **nội bộ của riêng bước OAEP** vì đây là giới hạn toán học cứng của kích
thước khoá 1024-bit, không phải lựa chọn tuỳ ý.

### Đây cũng là một phát hiện đáng đưa vào báo cáo

Mục 7 (`xaydung.md`) đã nhận xét *"RSA 1024-bit... chưa đủ an toàn cho triển khai
thực tế dài hạn"*. Giới hạn OAEP/SHA-512 nói trên là một minh chứng cụ thể, sâu hơn
cho nhận xét đó — nên trích dẫn trong phần "Phân tích, nhận xét đặc điểm thuật
toán" hoặc "Đề xuất cải tiến" (ví dụ: chuyển sang RSA-2048 sẽ đủ chỗ cho
OAEP-SHA512, hoặc chuyển hẳn sang ECC như đã đề xuất ở mục 8).

## Vì sao chữ ký (sig) chỉ ký metadata chứ không ký toàn bộ gói tin?

Chữ ký RSA-PKCS1v15+SHA-512 ký trên chuỗi canonical `device_id|timestamp|sensor_type`
(metadata) — KHÔNG ký trực tiếp lên `cipher`. Tính toàn vẹn của `cipher` được đảm
bảo độc lập bởi 2 lớp:

1. **AES-GCM tag** — sai lệch ngay khi `cipher` bị sửa dù chỉ 1 bit.
2. **SHA-512(nonce‖cipher‖tag)** — Server tự tính lại và so sánh với trường `hash`.

Đây chính là cơ chế "hai lớp phòng thủ độc lập" mô tả ở Luồng 3 (`xaydung.md` mục 5.3):
kẻ tấn công giữ nguyên `sig` hợp lệ (vì không đổi metadata) nhưng vẫn bị phát hiện
qua tag/hash khi sửa `cipher`.

## Chống Replay & Timestamp Bất Thường

`cloud_server/device_registry.py::DeviceRegistry` lưu `last_seen_timestamp` theo
từng `device_id`:

- Gói tin có `timestamp <= last_seen_timestamp[device_id]` → bị từ chối
  (`reason=replay_detected`).
- Gói tin có `timestamp` lệch quá `MAX_TIMESTAMP_SKEW_SECONDS` (mặc định 30s) so với
  giờ hệ thống Server → bị từ chối (`reason=timestamp_out_of_range`).

Yêu cầu ESP32 phải đồng bộ giờ qua NTP (xem `iot/src/main.cpp::syncTime()`) để
timestamp có ý nghĩa thực tế.
