#!/usr/bin/env bash
# Redaction audit - fail before committing evidence that leaks account identifiers,
# credentials, personal email or local paths.
#
#   ./scripts/redact-audit.sh             scan the working tree (default: git ls-files)
#   ./scripts/redact-audit.sh --staged    scan exactly the staged content (pre-commit)
#   ./scripts/redact-audit.sh --all       scan every visible file, tracked or not
#
# Exit 1 if any BLOCK-level match is found. WARN-level matches are reported and pass.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

MODE="${1:---tree}"
ALLOWLIST="scripts/redaction-allowlist.txt"
ACCOUNT_REDACTED='58********27'

usage() {
  sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

case "$MODE" in
  --staged|--tree|--all) ;;
  -h|--help) usage; exit 0 ;;
  *) echo "error: unknown argument '$MODE'" >&2; usage >&2; exit 2 ;;
esac

# severity | label | extended regex
RULES=(
  "BLOCK|account-id-in-arn|arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:"
  "BLOCK|account-id|(^|[^0-9])[0-9]{12}([^0-9]|$)"
  "BLOCK|access-key-id|(AKIA|ASIA)[0-9A-Z]{16}"
  # IAM unique IDs issued in the current format base32-encode the owning account ID after the
  # four-letter prefix, so they leak it exactly as an access key ID does. Current-format IDs have a
  # fifth character in Q-Z or 2-7; older ones (ANPAI.../ANPAJ..., mostly AWS-managed policies) do
  # not encode an account and stay at WARN. Newer AWS-managed policy IDs are in the current format
  # and get blocked too; they belong to AWS, but the rule cannot tell them apart without naming
  # this account's prefix. Mask as AIDA**************** (prefix kept, rest starred).
  "BLOCK|iam-unique-id-encodes-account|(AIDA|AROA|AGPA|ANPA|AIPA|APKA|ASCA)[Q-Z2-7][A-Z2-7]{15}"
  "WARN|iam-unique-id|(AIDA|AROA|AGPA|ANPA|AIPA|APKA)[0-9A-Z]{16}"
  "BLOCK|secret-access-key|aws_secret_access_key"
  "BLOCK|private-key-block|-----BEGIN [A-Z ]*PRIVATE KEY-----"
  "BLOCK|personal-email|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
  "BLOCK|local-home-path|/Users/[A-Za-z0-9._-]+"
  # North American phone numbers with separators: 202-555-0147, (202) 555-0147, +1 202.555.0147.
  # Separators are required so timestamps, IDs and digit runs do not match.
  "BLOCK|phone-number|(^|[^0-9])(\\+?1[ .-]?)?\\(?[2-9][0-9]{2}\\)?[ .-][0-9]{3}[ .-][0-9]{4}([^0-9]|$)"
  "WARN|aws-resource-id|(i|sg|vol|snap|ami|vpc|subnet|eni|rtb|igw|acl)-[0-9a-f]{8,17}"
  "WARN|ipv4|([0-9]{1,3}\\.){3}[0-9]{1,3}"
  "WARN|hostname-internal|[A-Za-z0-9-]+\\.(internal|compute\\.internal|local)\\b"
)

# Strings that look sensitive but are documented AWS examples or unroutable addresses.
EXEMPT_SNIPPET='AKIAIOSFODNN7EXAMPLE|ANPAIOSFODNN7EXAMPLE|123456789012|@example\.(com|org|net)|example@|0\.0\.0\.0|127\.0\.0\.1|255\.255\.255\.255|10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|58\*\*\*\*\*\*\*\*27'

is_allowlisted() {
  local path="$1" label="${2:-}" line l_path l_label
  [[ -f "$ALLOWLIST" ]] || return 1
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    l_path="${line%%|*}"
    l_label=""
    [[ "$line" == *"|"* ]] && l_label="${line#*|}"
    [[ -n "$l_label" && "$l_label" != "$label" ]] && continue
    [[ "$path" =~ $l_path ]] && return 0
  done < "$ALLOWLIST"
  return 1
}

list_files() {
  case "$MODE" in
    --staged)
      git diff --cached --name-only --diff-filter=ACM 2>/dev/null
      ;;
    --all)
      find . -type f \
        -not -path './.git/*' -not -path './.venv/*' \
        -not -name '.DS_Store' -not -name '*.pyc' 2>/dev/null | sed 's|^\./||'
      ;;
    *)
      if git rev-parse --git-dir >/dev/null 2>&1; then
        git ls-files 2>/dev/null
      else
        find . -type f \
          -not -path './.git/*' -not -path './.venv/*' \
          -not -name '.DS_Store' -not -name '*.pyc' 2>/dev/null | sed 's|^\./||'
      fi
      ;;
  esac
}

content_of() {
  case "$MODE" in
    --staged) git show ":$1" 2>/dev/null ;;
    *) cat -- "$1" 2>/dev/null ;;
  esac
}

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

blocks=0
warns=0
files_scanned=0

emit() {
  local sev="$1" label="$2" path="$3" where="$4" snippet="$5"
  snippet="${snippet//[$'\t']/ }"
  (( ${#snippet} > 150 )) && snippet="${snippet:0:147}..."
  printf '%s  %-22s %s%s\n           %s\n' "$sev" "$label" "$path" "$where" "$snippet"
  case "$sev" in
    BLOCK) blocks=$((blocks + 1)) ;;
    WARN)  warns=$((warns + 1)) ;;
  esac
}

while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  files_scanned=$((files_scanned + 1))

  # Filenames carry identifiers too - that is exactly how the Prowler export leaked.
  for rule in "${RULES[@]}"; do
    IFS='|' read -r sev label re <<< "$rule"
    is_allowlisted "$f" "$label" && continue
    if printf '%s' "$f" | grep -qE -e "$re"; then
      printf '%s' "$f" | grep -qE -e "$EXEMPT_SNIPPET" && continue
      emit "$sev" "$label" "$f" " (filename)" "$f"
    fi
  done

  # The content scan below skips binary files, and PDFs and Office documents are
  # binary (compressed). That is how a phone number reached git inside a PDF.
  # Since their contents cannot be checked, the files themselves are blocked.
  if [[ "$f" =~ \.(pdf|PDF|docx?|xlsx?|pptx?|odt|rtf)$ ]] && ! is_allowlisted "$f" "binary-document"; then
    emit "BLOCK" "binary-document" "$f" " (filename)" "contents cannot be scanned - keep documents out of the repo, or allowlist after reading it"
  fi

  content_of "$f" > "$TMP" 2>/dev/null || continue
  [[ -s "$TMP" ]] || continue
  grep -Iq . "$TMP" || continue   # skip binary

  for rule in "${RULES[@]}"; do
    IFS='|' read -r sev label re <<< "$rule"
    is_allowlisted "$f" "$label" && continue
    while IFS= read -r hit; do
      [[ -z "$hit" ]] && continue
      printf '%s' "$hit" | grep -qE -e "$EXEMPT_SNIPPET" && continue
      lineno="${hit%%:*}"
      emit "$sev" "$label" "$f" ":$lineno" "$hit"
    done < <(grep -nEI -e "$re" "$TMP" 2>/dev/null | head -3)
  done
done < <(list_files)

echo
echo "== redaction audit ($MODE)"
echo "   files scanned: $files_scanned"
echo "   BLOCK: $blocks    WARN: $warns"

if (( blocks > 0 )); then
  cat >&2 <<EOF

BLOCKED: $blocks match(es) must be redacted before this can be committed.

Account ids and ARNs:      s/582257684827/58********27/g
Emails:                    replace with a role address or remove the field
Access keys:               delete the credential, never store a redacted copy
Local paths:               s|/Users/[user]|~|  or strip from the evidence line
Phone numbers:             remove; contact details live on the resume, not in the repo
Binary documents:          move out of the repo (resumes, PDFs) - the gate cannot read them
Filenames:                 rename the artifact, then regenerate
EOF
  exit 1
fi

if (( warns > 0 )); then
  echo "   WARN items are acceptable in evidence but review them - resource ids and"
  echo "   private addresses are low risk, public IPs and hostnames are not."
fi

exit 0
