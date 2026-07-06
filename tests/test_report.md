# Test Report — Đề Tài 10

> Đối chiếu với "Kiểm thử bắt buộc" (`../../tailieu/huongdan.md` mục 3.4) và
> mục 5 ("Thử nghiệm") của `../../tailieu/xaydung.md`. Điền kết quả thực tế khi
> chạy trên phần cứng thật (ESP32 + PN532 + HC-SR04) hoặc qua `device_simulator/`.

## Cách lấy bằng chứng

Mỗi ca test dưới đây tương ứng 1 dòng trong `data/logs/cloud_transaction.log`
(status ACK/NACK + reason) và 1 lần chạy lệnh tương ứng ở README mục 5–6.
Dán log thật vào cột "Bằng chứng (log)" khi hoàn thiện báo cáo.

## Bảng Kết Quả

| # | Ca kiểm thử | Lệnh chạy | Kỳ vọng | Kết quả thực tế | Bằng chứng (log) |
|---|---|---|---|---|---|
| 1 | Thiết bị hợp lệ gửi dữ liệu | `simulate_device.py --device-id esp32-gate-001 --distance 30` | `ACK` | ⬜ | |
| 2 | Thiết bị giả mạo gửi dữ liệu | `simulate_device.py --device-id esp32-fake-999` | `REJECT unknown_device` | ⬜ | |
| 3 | Sửa giá trị cảm biến (tamper trực tiếp) | `simulate_device.py ... --tamper-cipher` | `NACK integrity` | ⬜ | |
| 3b | Sửa giá trị cảm biến (MITM giữa đường truyền) | `mitm_tamper.py` + `simulate_device.py --port 9001` | `NACK integrity` | ⬜ | |
| 4 | Gửi lại gói tin cũ (replay) | `simulate_device.py --save-packet` rồi `--replay-file` | Lần 1 `ACK`, lần 2 `NACK replay_detected` | ⬜ | |
| 5 | Timestamp bất thường | `simulate_device.py ... --timestamp-offset 999999` | `NACK timestamp_out_of_range` | ⬜ | |
| 6 | Log theo từng thiết bị | Chạy ≥2 device_id khác nhau, kiểm tra `data/samples/sensor_data_<device_id>.txt` riêng biệt | Mỗi thiết bị có file log riêng | ⬜ | |
| 7 | Baseline không bảo mật (Luồng 2 — đối chứng) | `server.py --baseline` + `baseline_fake_packet.py` | Server chấp nhận dữ liệu giả, không cảnh báo | ⬜ | |

## Đo Hiệu Năng (mục 6 báo cáo — `xaydung.md`)

| Kích thước payload | Thời gian mã hoá AES-GCM | Thời gian ký + xác thực RSA | Round-trip tổng |
|---|---|---|---|
| Gói nhỏ (~100 byte, JSON cảm biến) | | | |
| Gói lớn hơn (mô phỏng nhiều cảm biến/batch) | | | |

> Gợi ý đo: bọc `time.perf_counter()` quanh `aes_gcm_encrypt`/`sign_data` trong
> `device_simulator/simulate_device.py`, hoặc dùng `micros()` trong
> `iot/src/crypto_utils.cpp` khi chạy trên phần cứng thật.

## Ghi Chú

- Ca #3 và #3b đều dẫn tới cùng 1 loại lỗi (`integrity`) nhưng theo 2 cơ chế tấn công
  khác nhau (tự sửa vs. chặn giữa đường truyền) — nên trình bày cả hai trong báo cáo
  để thể hiện chiều sâu thử nghiệm.
- Ca #2 thực chất bị chặn ngay ở bước **handshake** (trước cả bước ký/mã hoá) vì
  Server kiểm tra `device_id` đã đăng ký chưa — đây là lớp phòng thủ đầu tiên,
  khác với lớp phòng thủ toàn vẹn ở ca #3.
