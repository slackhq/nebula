#!/bin/sh

# smoke-vagrant.sh for illumos: host3 runs in the OmniOS VM behind the `omnios` ssh alias instead of a vagrant box.

set -e -x

TARGET="$1"
VMDIR=/tmp/nebula-smoke

mkdir -p logs

NETWORK="nebula-smoke"

cleanup() {
    echo
    echo " *** cleanup"
    echo

    set +e
    if [ "$(jobs -r)" ]
    then
        docker kill lighthouse1 host2
    fi
    ssh omnios "test -f $VMDIR/pid && $VMSUDO xargs kill <$VMDIR/pid"
    docker network rm "$NETWORK" >/dev/null 2>&1
}

trap cleanup EXIT

docker network rm "$NETWORK" >/dev/null 2>&1 || true
for candidate in 172.30.0.0/24 172.31.0.0/24 10.98.0.0/24 10.99.0.0/24 192.168.230.0/24; do
    if docker network create --subnet "$candidate" "$NETWORK" >/dev/null 2>&1; then
        break
    fi
done
if ! docker network inspect "$NETWORK" >/dev/null 2>&1; then
    echo "failed to create $NETWORK: every candidate subnet is in use" >&2
    exit 1
fi

SUBNET="$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "$NETWORK")"
PREFIX="${SUBNET%/*}"
PREFIX="${PREFIX%.*}"
LIGHTHOUSE_IP="$PREFIX.2"
HOST2_IP="$PREFIX.3"

for f in build/host2.yml build/host3.yml; do
    sed "s|203\.0\.113\.|$PREFIX.|g" "$f" >"$f.tmp"
    mv "$f.tmp" "$f"
done

CONTAINER="nebula:${NAME:-smoke}"

# nebula needs root to plumb the tun device
VMSUDO="$(ssh omnios 'test "$(id -u)" = 0 || echo sudo')"

ssh omnios "rm -rf $VMDIR && mkdir -p $VMDIR"
rsync -a build/ "omnios:$VMDIR/"

docker run --name lighthouse1 --rm "$CONTAINER" -config lighthouse1.yml -test
docker run --name host2 --rm -v "$PWD/build/host2.yml:/nebula/host2.yml:ro" "$CONTAINER" -config host2.yml -test
ssh omnios "cd $VMDIR && ./$TARGET-nebula -config host3.yml -test"

docker run --name lighthouse1 --network "$NETWORK" --ip "$LIGHTHOUSE_IP" --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm "$CONTAINER" -config lighthouse1.yml 2>&1 | tee logs/lighthouse1 | sed -u 's/^/  [lighthouse1]  /' &
sleep 1
docker run --name host2 --network "$NETWORK" --ip "$HOST2_IP" -v "$PWD/build/host2.yml:/nebula/host2.yml:ro" --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm "$CONTAINER" -config host2.yml 2>&1 | tee logs/host2 | sed -u 's/^/  [host2]  /' &
sleep 1
ssh omnios "cd $VMDIR && $VMSUDO sh -c 'echo \$\$ >$VMDIR/pid && exec ./$TARGET-nebula -config host3.yml'" 2>&1 | tee logs/host3 | sed -u 's/^/  [host3]  /' &
sleep 15

set +x
echo
echo " *** Testing ping from lighthouse1"
echo
set -x
docker exec lighthouse1 ping -c1 192.168.100.2
docker exec lighthouse1 ping -c1 192.168.100.3

set +x
echo
echo " *** Testing ping from host2"
echo
set -x
docker exec host2 ping -c1 192.168.100.1
# Should fail because not allowed by host3 inbound firewall
! docker exec host2 ping -c1 192.168.100.3 -w5 || exit 1

set +x
echo
echo " *** Testing ping from host3"
echo
set -x
# illumos ping takes a timeout in seconds, -c is the traffic class
ssh omnios "/usr/sbin/ping 192.168.100.1 5"
ssh omnios "/usr/sbin/ping 192.168.100.2 5"

ssh omnios "$VMSUDO xargs kill <$VMDIR/pid && rm -f $VMDIR/pid"
docker exec host2 sh -c 'kill 1'
docker exec lighthouse1 sh -c 'kill 1'

for _ in $(seq 1 30); do
    [ -z "$(jobs -r)" ] && break
    sleep 1
done

if [ "$(jobs -r)" ]
then
    echo "nebula still running after SIGTERM sent" >&2
    exit 1
fi
