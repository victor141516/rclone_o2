#!/usr/bin/env bash
set -euo pipefail

RCLONE=${RCLONE:-./rclone}
REMOTE=${1:-${O2_SMOKE_REMOTE:-o2:}}
STAMP=$(date +%Y%m%d%H%M%S)
BASE_DIR="rclone-o2-smoke-${STAMP}-$$"
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rclone-o2-smoke.XXXXXX")

remote_path() {
	local rel=$1
	case "$REMOTE" in
		*:) printf '%s%s' "$REMOTE" "$rel" ;;
		*/) printf '%s%s' "$REMOTE" "$rel" ;;
		*) printf '%s/%s' "$REMOTE" "$rel" ;;
	esac
}

run() {
	printf '\n+'
	printf ' %q' "$@"
	printf '\n'
	"$@"
}

cleanup() {
	set +e
	run "$RCLONE" purge "$(remote_path "$BASE_DIR")" -vv >/dev/null 2>&1
	rm -rf "$TMP_DIR"
}
trap cleanup EXIT

printf 'Using rclone: %s\n' "$RCLONE"
printf 'Using remote: %s\n' "$REMOTE"
printf 'Smoke directory: %s\n' "$BASE_DIR"

printf 'hello from rclone O2 smoke %s\n' "$STAMP" >"$TMP_DIR/source.txt"
printf 'nested file from rclone O2 smoke %s\n' "$STAMP" >"$TMP_DIR/nested.txt"

run "$RCLONE" about "$REMOTE" -vv
run "$RCLONE" mkdir "$(remote_path "$BASE_DIR")" -vv
run "$RCLONE" copyto "$TMP_DIR/source.txt" "$(remote_path "$BASE_DIR/source.txt")" -vv
run "$RCLONE" lsf "$(remote_path "$BASE_DIR")" -vv

printf '\n+ %q cat %q -vv > %q\n' "$RCLONE" "$(remote_path "$BASE_DIR/source.txt")" "$TMP_DIR/cat.out"
"$RCLONE" cat "$(remote_path "$BASE_DIR/source.txt")" -vv >"$TMP_DIR/cat.out"
cmp "$TMP_DIR/source.txt" "$TMP_DIR/cat.out"

run "$RCLONE" moveto "$(remote_path "$BASE_DIR/source.txt")" "$(remote_path "$BASE_DIR/renamed.txt")" -vv
run "$RCLONE" mkdir "$(remote_path "$BASE_DIR/nested")" -vv
run "$RCLONE" copyto "$TMP_DIR/nested.txt" "$(remote_path "$BASE_DIR/nested/nested.txt")" -vv
run "$RCLONE" deletefile "$(remote_path "$BASE_DIR/nested/nested.txt")" -vv
run "$RCLONE" rmdir "$(remote_path "$BASE_DIR/nested")" -vv
run "$RCLONE" deletefile "$(remote_path "$BASE_DIR/renamed.txt")" -vv
run "$RCLONE" rmdir "$(remote_path "$BASE_DIR")" -vv

trap - EXIT
rm -rf "$TMP_DIR"

printf '\nO2 smoke test completed successfully.\n'
