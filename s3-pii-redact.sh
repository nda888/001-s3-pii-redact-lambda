#!/usr/bin/env bash
# =============================================================================
# s3-pii-redact.sh— S3 Event + Lambda + Comprehend
#
# Usage:
#   ./s3-pii-redact.sh setup              # create 2 buckets, IAM role, Lambda, S3 trigger
#   ./s3-pii-redact.sh test               # upload chat-001.txt, read chat-001-redacted.txt
#   ./s3-pii-redact.sh status             # show existing Lab resources
#   ./s3-pii-redact.sh cleanup --dry-run  # preview what will be deleted, deletes NOTHING
#   ./s3-pii-redact.sh cleanup            # preview -> type DELETE -> delete everything
#   ./s3-pii-redact.sh cleanup --yes      # preview -> delete without asking (-y = --yes)
#   ./s3-pii-redact.sh all                # setup -> test -> cleanup (still asks for DELETE)
#   ./s3-pii-redact.sh all -y             # setup -> test -> cleanup without asking (-y = --yes)
#
# Requires: AWS CLI v2, python3 (to build the zip), permissions for S3, IAM, Lambda, Logs.
# This script NEVER touches Demo 1 or Demo 2 resources (S3 Object Lambda).
# =============================================================================
set -Eeuo pipefail
# ----------------------------- Configuration ------------------------
export AWS_REGION="us-east-1"
export AWS_DEFAULT_REGION="us-east-1"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
RAW_BUCKET="chat-raw-${ACCOUNT_ID}"
RED_BUCKET="chat-redacted-${ACCOUNT_ID}"
FUNCTION="pii-redact"
ROLE="pii-redact-role"                       # role created by this script; Console-created roles get a -xxxx suffix
INLINE_POLICY="pii-redact-s3-comprehend"
BASIC_POLICY_ARN="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
LOG_GROUP="/aws/lambda/${FUNCTION}"
STATEMENT_ID="s3-invoke-${RAW_BUCKET}"
WORKDIR="${WORKDIR:-./s3-pii-redact-work}"
# --------------------------------- Helpers -----------------------------------
log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ✔ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  ⚠ %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m  ✖ %s\033[0m\n' "$*" >&2; exit 1; }
trap 'die "Lỗi ở dòng ${LINENO}: ${BASH_COMMAND}"' ERR
bucket_exists()    { aws s3api head-bucket --bucket "$1" >/dev/null 2>&1; }
function_exists()  { aws lambda get-function --function-name "$FUNCTION" >/dev/null 2>&1; }
role_exists()      { aws iam get-role --role-name "$1" >/dev/null 2>&1; }
log_group_exists() {
  aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP" \
    --query 'logGroups[0].logGroupName' --output text | grep -qx "$LOG_GROUP"
}
check_prereqs() {
  command -v aws >/dev/null || die "Chưa cài AWS CLI."
  command -v python3 >/dev/null || die "Chưa có python3 (dùng để nén zip)."
  aws --version 2>&1 | grep -q 'aws-cli/2' || warn "Nên dùng AWS CLI v2."
  mkdir -p "$WORKDIR"
  ok "Account ${ACCOUNT_ID}, region ${AWS_REGION}"
}
# Lambda roles: the script-created role + Console-created roles (pii-redact-role-xxxx) + the role attached to the function.
find_roles() {
  local found=() r
  if function_exists; then
    r="$(aws lambda get-function-configuration --function-name "$FUNCTION" --query Role --output text)"
    found+=("${r##*/}")
  fi
  role_exists "$ROLE" && found+=("$ROLE")
  while read -r r; do
    [[ -n "$r" && "$r" != "None" ]] && found+=("$r")
  done < <(aws iam list-roles --path-prefix /service-role/ \
    --query "Roles[?starts_with(RoleName, '${ROLE}-')].RoleName" --output text | tr '\t' '\n')
  [[ ${#found[@]} -gt 0 ]] || return 0
  printf '%s\n' "${found[@]}" | sort -u
}
# ---------------------------------- Setup ------------------------------------
write_lambda_code() {
  cat > "${WORKDIR}/lambda_function.py" <<'PY'
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
PY
  (cd "$WORKDIR" && rm -f pii-redact.zip && python3 -m zipfile -c pii-redact.zip lambda_function.py)
  ok "Đã đóng gói ${WORKDIR}/pii-redact.zip"
}
step1_buckets() {
  log "Bước 1 — Tạo 2 bucket: gốc và redacted"
  local b
  for b in "$RAW_BUCKET" "$RED_BUCKET"; do
    if bucket_exists "$b"; then
      ok "Bucket ${b} đã có, bỏ qua"
    else
      aws s3api create-bucket --bucket "$b" >/dev/null   # us-east-1 needs no LocationConstraint
      aws s3api wait bucket-exists --bucket "$b"
      ok "Đã tạo bucket ${b}"
    fi
    aws s3api put-public-access-block --bucket "$b" --public-access-block-configuration \
      BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  done
}
step2_role() {
  log "Bước 2 — IAM role ${ROLE} với quyền tối thiểu"
  if role_exists "$ROLE"; then
    ok "Role đã có, bỏ qua tạo mới"
  else
    aws iam create-role --role-name "$ROLE" --assume-role-policy-document '{
      "Version": "2012-10-17",
      "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    }' >/dev/null
    aws iam wait role-exists --role-name "$ROLE"
    ok "Đã tạo role"
  fi
  aws iam attach-role-policy --role-name "$ROLE" --policy-arn "$BASIC_POLICY_ARN"
  aws iam put-role-policy --role-name "$ROLE" --policy-name "$INLINE_POLICY" --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [
      {\"Sid\": \"ReadRawChats\", \"Effect\": \"Allow\", \"Action\": \"s3:GetObject\", \"Resource\": \"arn:aws:s3:::${RAW_BUCKET}/*\"},
      {\"Sid\": \"WriteRedactedChats\", \"Effect\": \"Allow\", \"Action\": \"s3:PutObject\", \"Resource\": \"arn:aws:s3:::${RED_BUCKET}/*\"},
      {\"Sid\": \"DetectPii\", \"Effect\": \"Allow\", \"Action\": \"comprehend:DetectPiiEntities\", \"Resource\": \"*\"}
    ]
  }"
  ok "Gắn AWSLambdaBasicExecutionRole (ghi log) + inline policy ${INLINE_POLICY}"
}
step3_lambda() {
  log "Bước 3 — Lambda ${FUNCTION} (Python 3.13, 256 MB, timeout 30 giây)"
  write_lambda_code
  if function_exists; then
    aws lambda update-function-code --function-name "$FUNCTION" --zip-file "fileb://${WORKDIR}/pii-redact.zip" >/dev/null
    aws lambda wait function-updated-v2 --function-name "$FUNCTION"
    ok "Function đã có, đã cập nhật code mới"
    return 0
  fi
  local role_arn="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE}" i
  # A newly created role takes a few seconds to become usable, so retry up to 6 times.
  for i in 1 2 3 4 5 6; do
    if aws lambda create-function --function-name "$FUNCTION" --runtime python3.13 \
         --handler lambda_function.lambda_handler --role "$role_arn" \
         --zip-file "fileb://${WORKDIR}/pii-redact.zip" --timeout 30 --memory-size 256 \
         --environment "Variables={DEST_BUCKET=${RED_BUCKET}}" >/dev/null 2>"${WORKDIR}/create.err"; then
      break
    fi
    grep -q 'cannot be assumed' "${WORKDIR}/create.err" || die "Tạo Lambda lỗi: $(cat "${WORKDIR}/create.err")"
    [[ $i -lt 6 ]] || die "Role vẫn chưa sẵn sàng sau 6 lần thử."
    echo "  … role chưa sẵn sàng, thử lại sau 10 giây (${i}/6)"
    sleep 10
  done
  aws lambda wait function-active-v2 --function-name "$FUNCTION"
  ok "Đã tạo Lambda ${FUNCTION}"
}
step4_trigger() {
  log "Bước 4 — S3 trigger: ${RAW_BUCKET} ObjectCreated -> ${FUNCTION}"
  local fn_arn
  fn_arn="$(aws lambda get-function-configuration --function-name "$FUNCTION" --query FunctionArn --output text)"
  if aws lambda get-policy --function-name "$FUNCTION" --query Policy --output text 2>/dev/null | grep -q "$STATEMENT_ID"; then
    ok "Quyền cho S3 gọi Lambda đã có"
  else
    aws lambda add-permission --function-name "$FUNCTION" --statement-id "$STATEMENT_ID" \
      --action lambda:InvokeFunction --principal s3.amazonaws.com \
      --source-arn "arn:aws:s3:::${RAW_BUCKET}" --source-account "$ACCOUNT_ID" >/dev/null
    ok "Đã cho phép S3 gọi Lambda (resource-based policy)"
  fi
  aws s3api put-bucket-notification-configuration --bucket "$RAW_BUCKET" --notification-configuration "{
    \"LambdaFunctionConfigurations\": [{\"Id\": \"pii-redact-on-create\", \"LambdaFunctionArn\": \"${fn_arn}\", \"Events\": [\"s3:ObjectCreated:*\"]}]
  }"
  ok "Đã gắn S3 Event Notification (All object create events)"
}
cmd_setup() {
  check_prereqs
  step1_buckets
  step2_role
  step3_lambda
  step4_trigger
  log "Setup Lab xong"
}
# ----------------------------------- Test ------------------------------------
cmd_test() {
  check_prereqs
  log "Bước 5 — Upload chat-001.txt và đọc bản đã che"
  cat > "${WORKDIR}/chat-001.txt" <<'EOF'
2026-11-12 09:15 Customer: Hi, I'm John Smith. My order has not arrived yet.
2026-11-12 09:16 Agent: Sorry about that. Can you confirm your address and phone number?
2026-11-12 09:17 Customer: Ship it to 100 Main Street, Any City, WA 98121. Call me at 206-555-0100.
2026-11-12 09:18 Customer: You can also email me at john.smith@example.com.
2026-11-12 09:19 Agent: Thanks John, we will resend the package today.
EOF
  aws s3 rm "s3://${RED_BUCKET}/chat-001-redacted.txt" --only-show-errors || true
  aws s3 cp "${WORKDIR}/chat-001.txt" "s3://${RAW_BUCKET}/chat-001.txt" --only-show-errors
  ok "Đã upload chat-001.txt, chờ Lambda xử lý"
  local i
  for i in $(seq 1 15); do
    if aws s3api head-object --bucket "$RED_BUCKET" --key chat-001-redacted.txt >/dev/null 2>&1; then
      aws s3 cp "s3://${RED_BUCKET}/chat-001-redacted.txt" "${WORKDIR}/chat-001-redacted.txt" --only-show-errors
      ok "Nội dung chat-001-redacted.txt:"
      sed 's/^/     /' "${WORKDIR}/chat-001-redacted.txt"
      return 0
    fi
    sleep 2
  done
  die "Sau 30 giây chưa thấy chat-001-redacted.txt. Xem log: CloudWatch ${LOG_GROUP}"
}
# --------------------------------- Status ------------------------------------
cmd_status() {
  check_prereqs
  log "Tài nguyên Lab"
  bucket_exists "$RAW_BUCKET" && ok "Bucket ${RAW_BUCKET}" || warn "Không có bucket ${RAW_BUCKET}"
  bucket_exists "$RED_BUCKET" && ok "Bucket ${RED_BUCKET}" || warn "Không có bucket ${RED_BUCKET}"
  function_exists && ok "Lambda ${FUNCTION}" || warn "Không có Lambda ${FUNCTION}"
  local r roles
  roles="$(find_roles)"
  if [[ -n "$roles" ]]; then while read -r r; do ok "IAM role ${r}"; done <<<"$roles"; else warn "Không có IAM role"; fi
  log_group_exists && ok "Log group ${LOG_GROUP}" || warn "Không có log group ${LOG_GROUP}"
}
# --------------------------------- Cleanup -----------------------------------
CLEANUP_FOUND=0
# Customer managed policies created by the Lambda Console (AWSLambdaBasicExecutionRole-<uuid>) attached to the role.
console_policies() {
  aws iam list-attached-role-policies --role-name "$1" \
    --query "AttachedPolicies[?starts_with(PolicyName, 'AWSLambdaBasicExecutionRole-')].PolicyArn" --output text | tr '\t' '\n' | grep -v '^None$' || true
}
preview_cleanup() {
  local tag="${1:-}" r p roles objs b
  log "Xem trước những gì sẽ bị xoá"
  if bucket_exists "$RAW_BUCKET"; then
    echo "  ${tag:+[$tag] }sẽ gỡ S3 Event Notification trên ${RAW_BUCKET}"; CLEANUP_FOUND=1
  fi
  if function_exists; then
    echo "  ${tag:+[$tag] }sẽ xoá Lambda ${FUNCTION}"; CLEANUP_FOUND=1
  fi
  if log_group_exists; then
    echo "  ${tag:+[$tag] }sẽ xoá log group ${LOG_GROUP}"; CLEANUP_FOUND=1
  fi
  roles="$(find_roles)"
  while read -r r; do
    [[ -n "$r" ]] || continue
    echo "  ${tag:+[$tag] }sẽ xoá IAM role ${r} (gỡ policy đang gắn, xoá inline policy)"; CLEANUP_FOUND=1
    while read -r p; do
      [[ -n "$p" ]] && echo "  ${tag:+[$tag] }sẽ xoá customer managed policy ${p##*/}"
    done < <(console_policies "$r")
  done <<<"$roles"
  for b in "$RAW_BUCKET" "$RED_BUCKET"; do
    bucket_exists "$b" || continue
    echo "  ${tag:+[$tag] }sẽ empty và xoá bucket ${b}, gồm:"
    objs="$(aws s3 rm "s3://${b}" --recursive --dryrun)"
    if [[ -n "$objs" ]]; then sed 's/^[[:space:]]*(dryrun) /    /' <<<"$objs"; else echo "    (bucket trống)"; fi
    CLEANUP_FOUND=1
  done
  echo "  ${tag:+[$tag] }sẽ xoá thư mục local ${WORKDIR}"
  [[ "$CLEANUP_FOUND" -eq 1 ]] || ok "Không còn tài nguyên Lab nào trên AWS"
}
delete_role() {
  local r="$1" p
  while read -r p; do
    [[ -n "$p" && "$p" != "None" ]] || continue
    aws iam detach-role-policy --role-name "$r" --policy-arn "$p"
  done < <(aws iam list-attached-role-policies --role-name "$r" --query 'AttachedPolicies[].PolicyArn' --output text | tr '\t' '\n')
  while read -r p; do
    [[ -n "$p" && "$p" != "None" ]] || continue
    aws iam delete-role-policy --role-name "$r" --policy-name "$p"
  done < <(aws iam list-role-policies --role-name "$r" --query 'PolicyNames[]' --output text | tr '\t' '\n')
  aws iam delete-role --role-name "$r"
  ok "Đã xoá IAM role ${r}"
}
delete_console_policy() {
  local p="$1" count i
  # IAM takes a few seconds to update the attachment count after detaching.
  for i in 1 2 3 4 5; do
    count="$(aws iam get-policy --policy-arn "$p" --query 'Policy.AttachmentCount' --output text)"
    [[ "$count" == "0" ]] && break
    sleep 3
  done
  if [[ "$count" != "0" ]]; then
    warn "Giữ lại ${p##*/}: vẫn còn gắn với ${count} chỗ khác"
    return 0
  fi
  aws iam delete-policy --policy-arn "$p"
  ok "Đã xoá customer managed policy ${p##*/}"
}
cmd_cleanup() {
  check_prereqs
  local mode="${1:-}"
  case "$mode" in
    ""|--yes|--dry-run) ;;
    -y) mode="--yes" ;;   # -y is short for --yes
    *) die "Tham số không hợp lệ: '${mode}' (chỉ nhận --dry-run, --yes hoặc -y)" ;;
  esac
  local tag=""
  [[ "$mode" == "--dry-run" ]] && tag="DRY-RUN"
  preview_cleanup "$tag"
  if [[ "$mode" == "--dry-run" ]]; then
    log "Dry-run xong, chưa xoá gì."
    return 0
  fi
  if [[ "$CLEANUP_FOUND" -eq 0 ]]; then
    rm -rf "$WORKDIR"
    log "Không có gì trên AWS để xoá."
    return 0
  fi
  if [[ "$mode" != "--yes" ]]; then
    local answer
    read -r -p "  Gõ DELETE để xoá đúng danh sách trên: " answer
    [[ "$answer" == "DELETE" ]] || die "Đã huỷ, không xoá gì."
  fi
  log "Xoá toàn bộ Lab"
  local roles r p b policies=()
  roles="$(find_roles)"            # fetch before deleting the function, because the role is read from the function config
  while read -r r; do
    [[ -n "$r" ]] || continue
    while read -r p; do [[ -n "$p" ]] && policies+=("$p"); done < <(console_policies "$r")
  done <<<"$roles"
  if bucket_exists "$RAW_BUCKET"; then
    aws s3api put-bucket-notification-configuration --bucket "$RAW_BUCKET" --notification-configuration '{}'
    ok "Đã gỡ S3 Event Notification"
  fi
  if function_exists; then
    aws lambda delete-function --function-name "$FUNCTION"
    ok "Đã xoá Lambda ${FUNCTION}"
  fi
  while read -r r; do
    [[ -n "$r" ]] || continue
    delete_role "$r"
  done <<<"$roles"
  for p in ${policies[@]+"${policies[@]}"}; do delete_console_policy "$p"; done
  # Delete the log group after the Lambda so the Lambda cannot recreate it by logging.
  if log_group_exists; then
    aws logs delete-log-group --log-group-name "$LOG_GROUP"
    ok "Đã xoá log group ${LOG_GROUP}"
  fi
  for b in "$RAW_BUCKET" "$RED_BUCKET"; do
    bucket_exists "$b" || continue
    aws s3 rm "s3://${b}" --recursive --only-show-errors
    aws s3api delete-bucket --bucket "$b"
    ok "Đã empty và xoá bucket ${b}"
  done
  rm -rf "$WORKDIR"
  log "Đã xoá sạch Lab"
}
# ----------------------------------- Main ------------------------------------
case "${1:-}" in
  setup)   cmd_setup ;;
  test)    cmd_test ;;
  status)  cmd_status ;;
  cleanup) cmd_cleanup "${2:-}" ;;
  all)
    # Validate arguments before setup, so a typo fails before creating any resources.
    case "${2:-}" in
      ""|-y|--yes|--dry-run) ;;
      *) die "Tham số không hợp lệ: '${2}' (chỉ nhận --dry-run, --yes hoặc -y)" ;;
    esac
    cmd_setup; cmd_test; cmd_cleanup "${2:-}" ;;
  *)       sed -n '2,17p' "$0"; exit 1 ;;   # print the "Usage" block at the top of the file
esac
