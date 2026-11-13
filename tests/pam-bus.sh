#!/bin/sh
# Normal-user builds; only disposable private-bus/mount fixtures run elevated.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ "$(id -u)" -ne 0 ] || { echo 'SKIP: invoke as the normal build user' >&2; exit 77; }
for command in cargo cc sudo unshare dbus-daemon busctl getfacl timeout python3; do
    command -v "$command" >/dev/null 2>&1 || { echo "SKIP: missing $command" >&2; exit 77; }
done
[ -n "${MULTISEATD_TEST_BINARY:-}" ] && [ -x "$MULTISEATD_TEST_BINARY" ] || {
    echo 'SKIP: provide explicit MULTISEATD_TEST_BINARY (non-VT, test-support build)' >&2; exit 77;
}
[ -n "${LIBSEAT_TEST_PREFIX:-}" ] && [ -d "$LIBSEAT_TEST_PREFIX" ] || {
    echo 'SKIP: provide explicit maintained C LIBSEAT_TEST_PREFIX (include/libseat.h and lib/libseat.so)' >&2; exit 77;
}
sudo -n true || exit 77
sudo -n unshare --mount --propagation private true || exit 77
build=$(mktemp -d /tmp/greetd-pam-build.XXXXXXXX)
trap 'rm -rf "$build"' EXIT HUP INT TERM
cc -shared -fPIC -Wall -Wextra -Werror "$repo/tests/fixtures/pam-seat.c" -lpam -o "$build/pam-seat.so"
cc -Wall -Wextra -Werror -I"$LIBSEAT_TEST_PREFIX/include" \
    "$repo/tests/fixtures/native-seat.c" -L"$LIBSEAT_TEST_PREFIX/lib" \
    -Wl,-rpath,"$LIBSEAT_TEST_PREFIX/lib" -lseat -o "$build/native-client"
CARGO_TARGET_DIR="$repo/target/pam-test" cargo build --manifest-path "$repo/Cargo.toml" \
    --locked -p greetd --features test-support
sudo -n env KEEP_FIXTURES="${KEEP_FIXTURES:-0}" \
    unshare --mount --propagation private -- timeout --signal=TERM --kill-after=5 120 \
    sh "$repo/tests/private-pam.sh" "$repo/target/pam-test/debug/greetd" \
    "$(realpath "$MULTISEATD_TEST_BINARY")" "$build/pam-seat.so" \
    "$repo/tests/fixtures/seat-entry.py" "$repo/tests/pam-bus.py" "$build/native-client"
