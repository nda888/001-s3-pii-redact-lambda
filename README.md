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
