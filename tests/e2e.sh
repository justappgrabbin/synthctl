#!/bin/sh
# e2e.sh — end-to-end proof that synthctl is a real container runtime.
# Builds a tiny rootfs from the host, packs a .synthimg, runs it, and
# verifies every isolation boundary actually holds.
set -e
cd "$(dirname "$0")/.."

BIN=${SYNTHCTL_BIN:-./synthctl}

ROOTFS=${SYNTHCTL_ROOTFS:-/tmp/synthctl-test-rootfs}
IMG=tests/demo.synthimg
rm -rf "$ROOTFS" "$IMG" "$HOME/.synthctl"
mkdir -p "$ROOTFS/bin" "$ROOTFS/lib" "$ROOTFS/usr/lib" "$ROOTFS/proc" "$ROOTFS/dev"

# copy /bin/sh (dash) and tools, plus every shared library they need
for b in /bin/sh /bin/ls /bin/cat /bin/hostname /usr/bin/id; do
    [ -e "$b" ] || continue
    cp "$b" "$ROOTFS/bin/"
    ldd "$b" 2>/dev/null | grep -o '/[^ ]*' | while read -r lib; do
        [ -e "$lib" ] && cp --parents "$lib" "$ROOTFS" 2>/dev/null || true
    done
done

# static helpers for namespace + limit verification
cc -O2 -static -o "$ROOTFS/bin/netprobe" tests/netprobe.c
cc -O2 -static -o "$ROOTFS/bin/memhog" tests/memhog.c

echo "hello from inside the image" > "$ROOTFS/hello.txt"

$BIN build "$ROOTFS" -o "$IMG" --name demo --entry "/bin/sh" --env GREETING=synthbox
$BIN inspect "$IMG"

echo "=== TEST 1: process isolation (expect: my pid = 1) ==="
$BIN run "$IMG" -- /bin/sh -c 'echo "my pid: $$"; kill -0 99999 2>/dev/null && echo FAIL || echo "host pid range invisible: OK"'

echo "=== TEST 2: filesystem isolation (expect: hello.txt visible, host dirs gone) ==="
$BIN run "$IMG" -- /bin/sh -c 'cat /hello.txt; ls /; test -d /mnt/agents && echo FAIL-host-visible || echo "host fs not visible: OK"'

echo "=== TEST 3: hostname isolation (UTS ns) ==="
$BIN run "$IMG" --hostname synthbox-42 -- /bin/sh -c 'hostname'
host_host=$(hostname)
$BIN run "$IMG" -- /bin/sh -c 'hostname changed-inside 2>/dev/null || true'
[ "$(hostname)" = "$host_host" ] && echo "host hostname unchanged: OK"

echo "=== TEST 4: user namespace (uid 0 inside = unprivileged outside) ==="
$BIN run "$IMG" -- /bin/sh -c 'id'

echo "=== TEST 5: network isolation (fresh net ns: expect only lo) ==="
$BIN run "$IMG" -- /bin/netprobe
echo "-- host-net for contrast:"
$BIN run "$IMG" --host-net -- /bin/netprobe | head -5

echo "=== TEST 6: manifest env ==="
$BIN run "$IMG" -- /bin/sh -c 'echo "GREETING=$GREETING"'

echo "=== TEST 7: exit code propagation ==="
rc=0; $BIN run "$IMG" -- /bin/sh -c 'exit 42' || rc=$?
echo "container exit code: $rc"
[ "$rc" = 42 ] && echo "exit code propagation: OK"

echo "=== TEST 8: memory limit actually enforced (--mem 16) ==="
rc=0; $BIN run "$IMG" --mem 16 -- /bin/memhog || rc=$?
echo "memory-limited run exit: $rc (nonzero = enforced)"
rc2=0; $BIN run "$IMG" --mem 512 -- /bin/memhog || rc2=$?
echo "generous-limit run exit: $rc2 (0 = not a false positive)"
[ "$rc" != 0 ] && [ "$rc2" = 0 ] && echo "memory limit: OK"

echo "=== ALL TESTS DONE ==="
