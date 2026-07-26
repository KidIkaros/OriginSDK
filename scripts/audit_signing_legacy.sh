#!/usr/bin/env bash
#
# audit_signing_legacy.sh — scan a Rust project for uses of removed
# `origin-crypto-sdk` 0.4-deprecated symbols.
#
# Per the SDK 0.6.0 breaking-change release, the following symbols
# were removed:
#
#   - `pub mod signing_legacy` (entire module)
#   - `pub use ...HybridSignatureOutput` (crate-root + via signing::*)
#   - `pub use ...HybridSigningKey` (crate-root + via signing::*)
#   - `pub use ...HybridVerifyingKey` (crate-root + via signing::*)
#
# Canonical replacement: `signing::hybrid::HybridSigningKeyBundle`
# (also re-exported at `origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle`).
#
# Usage:
#   audit_signing_legacy.sh [target_dir] [flags]
#
#     target_dir       Path to scan (default: ".")
#     --json           Emit machine-readable JSON output
#     --include-toml   Also scan .toml files (default: .rs only)
#     --include-md     Also scan .md files  (default: .rs only)
#     --quiet          Suppress the migration note on matches
#     -h, --help       Show this help and exit
#
# Exit codes:
#   0  No deprecated usage found (clean)
#   1  Deprecated usage found (one or more matches)
#   2  Invalid arguments or error
#
# Pattern notes:
#   - Word-boundary `\b` is used on the 3 struct names so we do NOT
#     false-flag the canonical `HybridSigningKeyBundle` replacement
#     (the substring "HybridSigningKey" within "HybridSigningKeyBundle"
#     has no word boundary between "y" and "B").
#   - The script does not scan `target/`, `.git/`, `node_modules/`,
#     `vendor/`, or any other build/VCS output directories.
#   - Requires either **ripgrep** (preferred) or **GNU grep** (which
#     supports `\b` in ERE). BSD `grep` (default on macOS) does NOT
#     honor `\b`; the script refuses to run with BSD grep to avoid
#     silently returning wrong/empty results. Install ripgrep on
#     macOS with `brew install ripgrep`.

set -uo pipefail

target_dir="."
emit_json=0
scan_toml=0
scan_md=0
quiet=0

# ── pattern table ────────────────────────────────────────────────────
# Each line: <rule_id><TAB><grep regex>
#
# The 3 struct names use word-boundary anchors so that the canonical
# replacement `HybridSigningKeyBundle` is NOT flagged. The trailing
# `\b` on each struct-name pattern ensures we don't accidentally match
# a future substring variant like `HybridVerifyingKeyBundle`.
declare -a patterns=(
  $'use_signing_legacy_module\tuse[ \\t]+(crate|origin_crypto_sdk)::?signing_legacy'
  $'use_full_path_signing_legacy\torigin_crypto_sdk::signing_legacy'
  $'bare_HybridSignatureOutput\t\\bHybridSignatureOutput\\b'
  $'bare_HybridSigningKey\t\\bHybridSigningKey\\b'
  $'bare_HybridVerifyingKey\t\\bHybridVerifyingKey\\b'
  $'use_signing_reexport_HybridSignatureOutput\tuse[ \\t]+origin_crypto_sdk::signing::HybridSignatureOutput\\b'
  $'use_signing_reexport_HybridSigningKey\tuse[ \\t]+origin_crypto_sdk::signing::HybridSigningKey\\b'
  $'use_signing_reexport_HybridVerifyingKey\tuse[ \\t]+origin_crypto_sdk::signing::HybridVerifyingKey\\b'
  $'use_crate_root_HybridSignatureOutput\tuse[ \\t]+origin_crypto_sdk::HybridSignatureOutput\\b'
  $'use_crate_root_HybridSigningKey\tuse[ \\t]+origin_crypto_sdk::HybridSigningKey\\b'
  $'use_crate_root_HybridVerifyingKey\tuse[ \\t]+origin_crypto_sdk::HybridVerifyingKey\\b'
)

# ── argument parsing ─────────────────────────────────────────────────

print_help() {
  sed -n '3,33p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)         emit_json=1; shift;;
    --include-toml) scan_toml=1; shift;;
    --include-md)   scan_md=1; shift;;
    --quiet)        quiet=1; shift;;
    -h|--help)      print_help; exit 0;;
    --)             shift; break;;
    -*)             printf 'Unknown flag: %s\n' "$1" >&2; exit 2;;
    *)              target_dir="$1"; shift;;
  esac
done

if [[ ! -d "$target_dir" ]]; then
  printf 'Error: target directory not found: %s\n' "$target_dir" >&2
  exit 2
fi

# ── build inclusion spec ─────────────────────────────────────────────

include_args=( --include='*.rs' )
[[ $scan_toml -eq 1 ]] && include_args+=( --include='*.toml' )
[[ $scan_md   -eq 1 ]] && include_args+=( --include='*.md' )

# ── pick a scanner ───────────────────────────────────────────────────
# Precedence: ripgrep > GNU grep > error.
#
# BSD `grep` (default on macOS) does NOT honor `\b` in ERE; the patterns
# here depend on `\b` for correctness. We probe for `\b` support to
# avoid silently returning wrong/empty results.
#
# Probe: feed a line that contains a word-boundary pattern into grep -E
# and check that it matches.
runner=""
runner_name=""
if command -v rg >/dev/null 2>&1; then
  declare -a rg_globs=()
  for inc in "${include_args[@]}"; do
    rg_globs+=( "--glob=${inc#--include=}" )
  done
  runner() {
    rg --line-number --no-heading --color=never \
       --glob '!target/**' --glob '!.git/**' --glob '!node_modules/**' --glob '!vendor/**' \
       "${rg_globs[@]}" \
       -e "$1" "$target_dir" 2>/dev/null || true
  }
  runner_name="ripgrep"
elif printf 'hello\nworld\n' | grep -E '\\bworld\\b' 2>/dev/null | grep -q 'world'; then
  runner() {
    grep -rnE --binary-files=without-match "$1" "${include_args[@]}" \
      "$target_dir" 2>/dev/null \
      | grep -vE '(^|/)(target|\.git|node_modules|vendor)/' \
      || true
  }
  runner_name="GNU grep"
else
  printf 'Error: this script requires ripgrep (preferred) or GNU grep.\n' >&2
  printf '\n' >&2
  printf 'macOS ships BSD grep which does not honor \\b in ERE.\n' >&2
  printf 'The patterns here depend on \\b (word boundaries) to distinguish\n' >&2
  printf 'deprecated `HybridSigningKey` from the canonical replacement\n' >&2
  printf '`HybridSigningKeyBundle` — without \\b, the script would\n' >&2
  printf 'silently return wrong results.\n' >&2
  printf '\n' >&2
  printf 'Install ripgrep: brew install ripgrep   (or: brew install grep)\n' >&2
  exit 2
fi

# ── run scans ────────────────────────────────────────────────────────

findings=()
for entry in "${patterns[@]}"; do
  rule_id="${entry%%$'\t'*}"
  pattern="${entry#*$'\t'}"
  [[ -z "$pattern" ]] && continue
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    findings+=( "${rule_id}|${line}" )
  done < <(runner "$pattern")
done

# Deduplicate by location (one location may match multiple rules; keep first)
declare -A seen
unique=()
for entry in "${findings[@]}"; do
  loc="${entry#*|}"
  if [[ -z "${seen[$loc]:-}" ]]; then
    seen[$loc]=1
    unique+=( "$entry" )
  fi
done

# Stable sort by location
if [[ ${#unique[@]} -gt 0 ]]; then
  IFS=$'\n' sorted=($(printf '%s\n' "${unique[@]}" | LC_ALL=C sort -t'|' -k2,2))
  unset IFS
  unique=("${sorted[@]}")
fi

# ── output ───────────────────────────────────────────────────────────

if [[ ${#unique[@]} -eq 0 ]]; then
  if [[ $emit_json -eq 1 ]]; then
    printf '{"target":"%s","clean":true,"findings":[]}\n' "$target_dir"
  else
    printf '✓ Clean — no deprecated origin-crypto-sdk 0.4-era symbols in %s\n' "$target_dir"
  fi
  exit 0
fi

if [[ $emit_json -eq 1 ]]; then
  printf '{"target":"%s","clean":false,"findings":[\n' "$target_dir"
  first=1
  for entry in "${unique[@]}"; do
    rule_id="${entry%%|*}"
    loc="${entry#*|}"
    path="${loc%%:*}"
    rest="${loc#*:}"
    lineno="${rest%%:*}"
    snippet="${rest#*:}"
    escaped_snippet=$(printf '%s' "$snippet" \
                      | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g')
    [[ $first -eq 0 ]] && printf ',\n'
    first=0
    printf '  {"rule":"%s","file":"%s","line":%s,"snippet":"%s"}' \
           "$rule_id" "$path" "$lineno" "$escaped_snippet"
  done
  printf '\n]}\n'
else
  printf '✗ Deprecated usage of origin-crypto-sdk 0.4-era symbols found in %s\n\n' "$target_dir"
  if [[ $quiet -eq 0 ]]; then
    printf 'Migration note: these symbols were removed in origin-crypto-sdk 0.6.0.\n'
    printf '  Use `signing::hybrid::HybridSigningKeyBundle` instead.\n'
    printf '  See MIGRATION.md in the SDK repo for the 0.5.x → 0.6 transition guide.\n\n'
  fi
  printf 'Findings (%d) [scanner=%s]:\n' "${#unique[@]}" "$runner_name"
  for entry in "${unique[@]}"; do
    rule_id="${entry%%|*}"
    loc="${entry#*|}"
    printf '  [%s] %s\n' "$rule_id" "$loc"
  done
fi

exit 1
