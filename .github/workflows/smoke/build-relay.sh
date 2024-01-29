#!/bin/sh

set -e -x

rm -rf ./build
mkdir ./build

(
    cd build

    cp ../../../../build/linux-amd64/nebula .
    cp ../../../../build/linux-amd64/nebula-cert .

    HOST="lighthouse1" AM_LIGHTHOUSE=true ../genconfig.sh >lighthouse1.yml <<EOF
relay:
  am_relay: true
EOF

    export LIGHTHOUSES="192.168.100.1 172.17.0.2:4242"
    export REMOTE_ALLOW_LIST='{"172.17.0.4/32": false, "172.17.0.5/32": false}'

    HOST="host2" ../genconfig.sh >host2.yml <<EOF
relay:
  relays:
    - 192.168.100.1
EOF

    export REMOTE_ALLOW_LIST='{"172.17.0.3/32": false}'

    HOST="host3" ../genconfig.sh >host3.yml

    HOST="host4" ../genconfig.sh >host4.yml <<EOF
relay:
  use_relays: false
EOF

    ../../../../nebula-cert ca -name "Smoke Test"
    ../../../../nebula-cert sign -name "lighthouse1" -groups "lighthouse,lighthouse1" -ip "192.168.100.1/24"
    ../../../../nebula-cert sign -name "host2" -groups "host,host2" -ip "192.168.100.2/24"
    ../../../../nebula-cert sign -name "host3" -groups "host,host3" -ip "192.168.100.3/24"
    ../../../../nebula-cert sign -name "host4" -groups "host,host4" -ip "192.168.100.4/24"
)

docker build -t nebula:smoke-relay .
