#!/bin/sh

set -e -x

rm -rf ./build
mkdir ./build

if [ "$SMOKE_OVERLAY_IPV6" ]
then
    LIGHTHOUSE_NIP="fd00:4242:0:0:0:ffff:c0a8:6401"
    HOST2_NIP="fd00:4242:0:0:0:ffff:c0a8:6402"
    HOST3_NIP="fd00:4242:0:0:0:ffff:c0a8:6403"
    HOST4_NIP="fd00:4242:0:0:0:ffff:c0a8:6404"
else
    LIGHTHOUSE_NIP="192.168.100.1"
    HOST2_NIP="192.168.100.2"
    HOST3_NIP="192.168.100.3"
    HOST4_NIP="192.168.100.4"
fi

# Smoke containers run on a dedicated docker network whose subnet is allocated
# at smoke time, not known at build time. Configs are written with TEST-NET-3
# placeholder IPs (RFC 5737) and smoke.sh / smoke-vagrant.sh / smoke-relay.sh
# sed the real container IPs in before starting nebula.
#
# Placeholder mapping (last octet == fixed container slot):
#   203.0.113.2 -> lighthouse1, 203.0.113.3 -> host2,
#   203.0.113.4 -> host3,       203.0.113.5 -> host4.
LIGHTHOUSE_IP="203.0.113.2"

(
    cd build

    cp ../../../../build/linux-amd64/nebula .
    cp ../../../../build/linux-amd64/nebula-cert .

    if [ "$1" ]
    then
        cp "../../../../build/$1/nebula" "$1-nebula"
    fi

    HOST="lighthouse1" \
        AM_LIGHTHOUSE=true \
        ../genconfig.sh >lighthouse1.yml

    HOST="host2" \
        LIGHTHOUSES="$LIGHTHOUSE_NIP $LIGHTHOUSE_IP:4242" \
        ../genconfig.sh >host2.yml

    HOST="host3" \
        LIGHTHOUSES="$LIGHTHOUSE_NIP $LIGHTHOUSE_IP:4242" \
        INBOUND='[{"port": "any", "proto": "icmp", "group": "lighthouse"}]' \
        ../genconfig.sh >host3.yml

    HOST="host4" \
        LIGHTHOUSES="$LIGHTHOUSE_NIP $LIGHTHOUSE_IP:4242" \
        OUTBOUND='[{"port": "any", "proto": "icmp", "group": "lighthouse"}]' \
        ../genconfig.sh >host4.yml

    ../../../../nebula-cert ca -curve "${CURVE:-25519}" -name "Smoke Test"
    ../../../../nebula-cert sign -name "lighthouse1" -groups "lighthouse,lighthouse1" -ip "$LIGHTHOUSE_NIP/24"
    ../../../../nebula-cert sign -name "host2" -groups "host,host2" -ip "$HOST2_NIP/24"
    ../../../../nebula-cert sign -name "host3" -groups "host,host3" -ip "$HOST3_NIP/24"
    ../../../../nebula-cert sign -name "host4" -groups "host,host4" -ip "$HOST4_NIP/24"
)

docker build -t "nebula:${NAME:-smoke}" .
