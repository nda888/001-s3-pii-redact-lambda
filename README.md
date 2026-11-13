# s3-pii-redact-lambda

Che thông tin cá nhân (PII – Personally Identifiable Information) ngay khi ghi file: mỗi khi có file chat mới vào bucket gốc, S3 Event tự gọi Lambda. Lambda gửi nội dung sang Amazon Comprehend (DetectPiiEntities) để tìm PII, thay PII bằng dấu *, rồi lưu bản đã che sang bucket redacted. Người đọc chỉ được vào bucket redacted, không truy cập được bucket gốc.

![S3 Event PII Redact Lambda Trigger](image/s3-pii-redact-lambda-trigger.png)

## Luồng hoạt động

| Bước | Hành động | Ai thực hiện |
|------|-----------|--------------|
| ① | `PutObject` file chat (còn PII) vào bucket gốc | App chat |
| ② | S3 phát `ObjectCreated` event bất đồng bộ (nét đứt) tới Lambda | S3 |
| ③ | Lambda gọi `DetectPiiEntities` để phát hiện entity PII | Lambda → Comprehend |
| ④ | Lambda ghi `chats/chat-002-redacted.txt` sang bucket redacted | Lambda |
| ⑤ | `GetObject` bản đã che, chỉ quyền đọc | QC provider |
