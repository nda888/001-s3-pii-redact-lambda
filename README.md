# s3-pii-redact-lambda

Redact Personally Identifiable Information (PII) **on write**: file chat được ghi vào bucket gốc, S3 Event kích hoạt Lambda, Lambda gọi Amazon Comprehend `DetectPiiEntities` rồi ghi bản đã che sang bucket redacted. Người đọc không vào được bucket gốc.

![S3 Event PII Redact Lambda Trigger](image/s3-pii-redact-lambda-trigger.png)

Sơ đồ nguồn (chỉnh sửa bằng draw.io): [`diagram/S3-Event-PII-Redact-Lambda-Trigger.drawio`](diagram/S3-Event-PII-Redact-Lambda-Trigger.drawio)

## Luồng hoạt động

| Bước | Hành động | Ai thực hiện |
|------|-----------|--------------|
| ① | `PutObject` file chat (còn PII) vào bucket gốc | App chat |
| ② | S3 phát `ObjectCreated` event bất đồng bộ (nét đứt) tới Lambda | S3 |
| ③ | Lambda gọi `DetectPiiEntities` để phát hiện entity PII | Lambda → Comprehend |
| ④ | Lambda ghi `chats/chat-002-redacted.txt` sang bucket redacted | Lambda |
| ⑤ | `GetObject` bản đã che, chỉ quyền đọc | QC provider |

## Chi tiết xử lý trong Lambda

- Đọc object theo `bucket` + `key` trong event; key được `unquote_plus` vì event trả key đã URL-encode.
- Guard chống vòng lặp vô hạn: nếu `src_bucket == DEST_BUCKET` thì raise lỗi ngay.
- Text được chia chunk ≤ 90 KB (giới hạn 100 KB của `DetectPiiEntities`), cắt theo ranh giới dòng để không chẻ đôi entity.
- Mỗi entity có `Score >= CONFIDENCE_THRESHOLD` (mặc định 0.5) và thuộc `PII_ENTITY_TYPES` (mặc định `ALL`) bị thay **từng ký tự** bằng `MASK_CHARACTER` (mặc định `*`), giữ nguyên độ dài văn bản.
- Key đầu ra: chèn `-redacted` trước phần mở rộng — `chats/chat-001.txt` → `chats/chat-001-redacted.txt`.
- `PII_ENTITY_TYPES`, `LANGUAGE_CODE`, `CONFIDENCE_THRESHOLD`, `MASK_CHARACTER` cấu hình qua biến môi trường; `DEST_BUCKET` là bắt buộc.

## Nguyên tắc quyền

- App chat chỉ có quyền `PutObject` vào bucket gốc.
- QC provider chỉ có quyền `GetObject` trên bucket redacted, không có quyền vào bucket gốc.
- Lambda có quyền đọc bucket gốc, ghi bucket redacted và gọi `comprehend:DetectPiiEntities`.

Tham chiếu triển khai trong workspace bài lab: `redact_pii_lambda.py`, `s3-pii-redact.sh`, `pii-redact-s3-comprehend.json`.
