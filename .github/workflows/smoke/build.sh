#!/bin/sh

set -e -x

rm -rf ./build
mkdir ./build

# TODO: Assumes your docker bridge network is a /24, and the first container that launches will be .1
# - We could make this better by launching the lighthouse first and then fetching what IP it is.
NET="$(docker network inspect bridge -f '{{ range .IPAM.Config }}{{ .Subnet }}{{ end }}' | cut -d. -f1-3)"

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
        LIGHTHOUSES="192.168.100.1 $NET.2:4242" \
        ../genconfig.sh >host2.yml

    HOST="host3" \
        LIGHTHOUSES="192.168.100.1 $NET.2:4242" \
        INBOUND='[{"port": "any", "proto": "icmp", "group": "lighthouse"}]' \
        ../genconfig.sh >host3.yml

    HOST="host4" \
        LIGHTHOUSES="192.168.100.1 $NET.2:4242" \
        OUTBOUND='[{"port": "any", "proto": "icmp", "group": "lighthouse"}]' \
        ../genconfig.sh >host4.yml

    ../../../../nebula-cert ca -curve "${CURVE:-25519}" -name "Smoke Test"
    ../../../../nebula-cert sign -name "lighthouse1" -groups "lighthouse,lighthouse1" -ip "192.168.100.1/24"
    ../../../../nebula-cert sign -name "host2" -groups "host,host2" -ip "192.168.100.2/24"
    ../../../../nebula-cert sign -name "host3" -groups "host,host3" -ip "192.168.100.3/24"
    ../../../../nebula-cert sign -name "host4" -groups "host,host4" -ip "192.168.100.4/24"
)

docker build -t "nebula:${NAME:-smoke}" .
