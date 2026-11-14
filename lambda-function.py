"""Redact PII on write: S3 ObjectCreated -> Comprehend -> <name>-redacted<ext> in DEST_BUCKET.
Env: DEST_BUCKET (required, not the source bucket), MASK_CHARACTER="*",
PII_ENTITY_TYPES="ALL", LANGUAGE_CODE="en", CONFIDENCE_THRESHOLD="0.5".
"""
import os
import urllib.parse
import boto3
s3 = boto3.client("s3")
comprehend = boto3.client("comprehend")
DEST_BUCKET = os.environ["DEST_BUCKET"]
MASK_CHARACTER = os.environ.get("MASK_CHARACTER", "*")
PII_ENTITY_TYPES = {t.strip() for t in os.environ.get("PII_ENTITY_TYPES", "ALL").split(",") if t.strip()}
LANGUAGE_CODE = os.environ.get("LANGUAGE_CODE", "en")
CONFIDENCE_THRESHOLD = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.5"))
MAX_CHUNK_BYTES = 90_000  # DetectPiiEntities accepts up to 100 KB per call
if len(MASK_CHARACTER) != 1:
    raise ValueError("MASK_CHARACTER must be exactly one character")
def lambda_handler(event, context):
    results = []
    for record in event.get("Records", []):
        src_bucket = record["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"], encoding="utf-8")  # event keys are URL-encoded
        if src_bucket == DEST_BUCKET:
            raise ValueError(f"Source bucket equals DEST_BUCKET ({src_bucket}): would invoke itself forever")
        text = s3.get_object(Bucket=src_bucket, Key=key)["Body"].read().decode("utf-8")
        redacted, masked = redact(text)
        out_key = redacted_key(key)
        s3.put_object(Bucket=DEST_BUCKET, Key=out_key, Body=redacted.encode("utf-8"), ContentType="text/plain; charset=utf-8")
        print(f"s3://{src_bucket}/{key} -> s3://{DEST_BUCKET}/{out_key}: masked {masked} PII entities")
        results.append({"key": out_key, "pii_masked": masked})
    return {"redacted": results}
def redacted_key(key):
    """chats/chat-001.txt -> chats/chat-001-redacted.txt (suffix goes before the extension)."""
    root, ext = os.path.splitext(key)
    return f"{root}-redacted{ext}"
def redact(text):
    """Replace every character of each PII entity with MASK_CHARACTER (keeps length)."""
    chars = list(text)
    masked = 0
    offset = 0
    for chunk in split_chunks(text):
        if chunk.strip():
            for entity in comprehend.detect_pii_entities(Text=chunk, LanguageCode=LANGUAGE_CODE)["Entities"]:
                if not should_mask(entity):
                    continue
                begin = offset + entity["BeginOffset"]
                end = min(offset + entity["EndOffset"], len(chars))  # EndOffset is exclusive
                chars[begin:end] = MASK_CHARACTER * (end - begin)
                masked += 1
        offset += len(chunk)
    return "".join(chars), masked
def should_mask(entity):
    if entity["Score"] < CONFIDENCE_THRESHOLD:
        return False
    return "ALL" in PII_ENTITY_TYPES or entity["Type"] in PII_ENTITY_TYPES
def split_chunks(text):
    """Split on line boundaries into chunks <= MAX_CHUNK_BYTES so no entity is cut mid-line."""
    chunk, size = [], 0
    for line in text.splitlines(keepends=True):
        for piece in split_long_line(line):
            piece_size = len(piece.encode("utf-8"))
            if chunk and size + piece_size > MAX_CHUNK_BYTES:
                yield "".join(chunk)
                chunk, size = [], 0
            chunk.append(piece)
            size += piece_size
    if chunk:
        yield "".join(chunk)
def split_long_line(line):
    """Hard-split a line longer than MAX_CHUNK_BYTES (UTF-8 is at most 4 bytes per char)."""
    step = MAX_CHUNK_BYTES // 4
    if len(line.encode("utf-8")) <= MAX_CHUNK_BYTES:
        return [line]
    return [line[i:i + step] for i in range(0, len(line), step)]
