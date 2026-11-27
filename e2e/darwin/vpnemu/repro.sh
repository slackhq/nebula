#!/bin/sh
# Reports where traffic to nebula peers goes before, during and after a vpnemu exit node.
#
# usage: sudo ./repro.sh -n <nebula binary> -c <nebula config> -p <peer vpn addr> [-p <peer>...]
#                        [-m claim|exclude] [-k <keep interfaces>]
#
# Each peer should answer pings over the overlay. A healthy run shows the nebula utun as egress
# and the ping working in all three phases.
set -u

MODE=claim
KEEP=en0
PEERS=""
NEBULA=""
CONFIG=""
while getopts n:c:p:m:k: o; do
	case $o in
	n) NEBULA=$OPTARG ;;
	c) CONFIG=$OPTARG ;;
	p) PEERS="$PEERS $OPTARG" ;;
	m) MODE=$OPTARG ;;
	k) KEEP=$OPTARG ;;
	*) exit 2 ;;
	esac
done
if [ -z "$NEBULA" ] || [ -z "$CONFIG" ] || [ -z "$PEERS" ]; then
	sed -n '4,5p' "$0"
	exit 2
fi

HERE=$(cd "$(dirname "$0")" && pwd)
VPNEMU=${VPNEMU:-$HERE/vpnemu}
LOG=$(mktemp -t nebula-repro)

report() {
	for p in $PEERS; do
		case $p in
		*:*) fam=-inet6 ping=ping6 ;;
		*) fam=-inet ping="ping -t 3" ;;
		esac
		egress=$(route -n get $fam "$p" 2>/dev/null | awk '/interface:/{print $2}')
		if $ping -c 2 "$p" >/dev/null 2>&1; then ok=ok; else ok=FAIL; fi
		printf '%-8s %-24s egress=%-8s ping=%s\n' "$1" "$p" "${egress:-none}" "$ok"
	done
}

cleanup() {
	[ -n "${EMU:-}" ] && kill "$EMU" 2>/dev/null
	[ -n "${NEB:-}" ] && kill "$NEB" 2>/dev/null
	wait 2>/dev/null
}
trap cleanup EXIT INT TERM

"$NEBULA" -config "$CONFIG" >"$LOG" 2>&1 &
NEB=$!
sleep 3
if ! kill -0 $NEB 2>/dev/null; then
	echo "nebula exited:"
	tail -5 "$LOG"
	exit 1
fi
echo "nebula on $(grep -o 'interface=utun[0-9]*' "$LOG" | head -1 | cut -d= -f2), log in $LOG"
report before

"$VPNEMU" -mode "$MODE" -keep "$KEEP" &
EMU=$!
sleep 3
report during

kill $EMU
wait $EMU 2>/dev/null
EMU=
sleep 2
report after

grep -E 'level=(WARN|ERROR).*(route|Route)' "$LOG"
