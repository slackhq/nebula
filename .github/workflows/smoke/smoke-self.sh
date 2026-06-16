#!/bin/bash

# A host must be able to reach its own overlay address. Where the kernel sends
# that traffic through the tun rather than over loopback, nebula sees it and
# hands it straight back (immediatelyForwardToSelf), and whether the kernel
# accepts what comes back is only answerable against a real kernel. Runs one
# nebula on this machine as root and aims every probe at its own address.

set -e -x

set -o pipefail

V4=192.0.2.1
V6=2001:db8::1

case "$(uname -s)" in
    Darwin) TUN_DEV=utun ;;
    *) TUN_DEV=tun0 ;;
esac

ROOT="$(cd ../../.. && pwd)"

rm -rf build/self
mkdir -p build/self
cd build/self

cleanup() {
    echo
    echo " *** cleanup"
    echo

    set +e
    if [ -n "$NEBULA_PID" ]
    then
        sudo kill "$NEBULA_PID"
    fi
    { kill $(jobs -p); wait; } 2>/dev/null
    sed 's/^/  [self]  /' nebula.log
}

trap cleanup EXIT

# perl is on every platform this runs on; timeout(1) is not.
alarm() {
    perl -e 'alarm shift; exec @ARGV' "$@"
}

RESULTS=""
FAILED=""
probe() {
    local name="$1"
    shift
    if "$@"
    then
        RESULTS="$RESULTS $name=ok"
    else
        RESULTS="$RESULTS $name=FAIL"
        FAILED="$FAILED $name"
    fi
}

# Send one datagram, then wait for the listener to have written it out.
udp_probe() {
    echo self | alarm 5 nc -u -w1 "$1" 3000 || true
    set +x
    for _ in $(seq 1 20)
    do
        if grep -q self "$2"
        then
            set -x
            return 0
        fi
        sleep 0.25
    done
    set -x
    return 1
}

"$ROOT/nebula-cert" ca -name "Smoke Test"
"$ROOT/nebula-cert" sign -name self -networks "$V4/24,$V6/64"

HOST=self AM_LIGHTHOUSE=true TUN_DEV="$TUN_DEV" ../../genconfig.sh >self.yml

"$ROOT/nebula" -config self.yml -test

sudo -v
sudo "$ROOT/nebula" -config self.yml >nebula.log 2>&1 &
NEBULA_PID=$!

for _ in $(seq 1 40)
do
    ifconfig | grep "inet6 $V6 " >/dev/null && break
    sleep 0.25
done
ifconfig | grep "inet $V4 "
ifconfig | grep "inet6 $V6 "

nc -l "$V4" 2000 >/dev/null &
nc -l "$V6" 2000 >/dev/null &
nc -u -l "$V4" 3000 >udp4.txt &
nc -u -l "$V6" 3000 >udp6.txt &
sleep 1

set +x
echo
echo " *** Testing self traffic from $V4"
echo
set -x
probe icmp4 alarm 5 ping -c1 "$V4"
probe tcp4 alarm 5 nc -z "$V4" 2000
probe udp4 udp_probe "$V4" udp4.txt

set +x
echo
echo " *** Testing self traffic from $V6"
echo
set -x
probe icmp6 alarm 5 ping6 -c1 "$V6"
probe tcp6 alarm 5 nc -z "$V6" 2000
probe udp6 udp_probe "$V6" udp6.txt

set +x
echo
echo " *** self traffic:$RESULTS"
echo
if [ -n "$FAILED" ]
then
    echo "self traffic failed:$FAILED" >&2
    exit 1
fi
