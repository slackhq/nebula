#!/bin/bash

set -e -x

set -o pipefail

mkdir -p logs

NETWORK="nebula-smoke"

cleanup() {
    echo
    echo " *** cleanup"
    echo

    set +e
    if [ "$(jobs -r)" ]
    then
        docker kill lighthouse1 host2 host3 host4
    fi
    docker network rm "$NETWORK" >/dev/null 2>&1
}

trap cleanup EXIT

# Create a dedicated smoke network with an explicit subnet (required for --ip
# below). Probe a short list of candidates so a locally-used range doesn't
# fail the whole test — we only need one to be free.
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

# Derive container IPs from the network's assigned subnet. Slots: .2 lighthouse1,
# .3 host2, .4 host3, .5 host4 — matches the placeholders in build.sh.
SUBNET="$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "$NETWORK")"
PREFIX="${SUBNET%/*}"
PREFIX="${PREFIX%.*}"
LIGHTHOUSE_IP="$PREFIX.2"
HOST2_IP="$PREFIX.3"
HOST3_IP="$PREFIX.4"
HOST4_IP="$PREFIX.5"

# Sed the placeholder TEST-NET-3 IPs in the host configs to the real ones.
# build/lighthouse1.yml has no IPs to rewrite so it's skipped.
for f in build/host2.yml build/host3.yml build/host4.yml; do
    sed "s|203\.0\.113\.|$PREFIX.|g" "$f" >"$f.tmp"
    mv "$f.tmp" "$f"
done

CONTAINER="nebula:${NAME:-smoke}"

docker run --name lighthouse1 --rm "$CONTAINER" -config lighthouse1.yml -test
docker run --name host2 --rm -v "$PWD/build/host2.yml:/nebula/host2.yml:ro" "$CONTAINER" -config host2.yml -test
docker run --name host3 --rm -v "$PWD/build/host3.yml:/nebula/host3.yml:ro" "$CONTAINER" -config host3.yml -test
docker run --name host4 --rm -v "$PWD/build/host4.yml:/nebula/host4.yml:ro" "$CONTAINER" -config host4.yml -test

docker run --name lighthouse1 --network "$NETWORK" --ip "$LIGHTHOUSE_IP" --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm "$CONTAINER" -config lighthouse1.yml 2>&1 | tee logs/lighthouse1 | sed -u 's/^/  [lighthouse1]  /' &
sleep 1
docker run --name host2 --network "$NETWORK" --ip "$HOST2_IP" -v "$PWD/build/host2.yml:/nebula/host2.yml:ro" --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm "$CONTAINER" -config host2.yml 2>&1 | tee logs/host2 | sed -u 's/^/  [host2]  /' &
sleep 1
docker run --name host3 --network "$NETWORK" --ip "$HOST3_IP" -v "$PWD/build/host3.yml:/nebula/host3.yml:ro" --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm "$CONTAINER" -config host3.yml 2>&1 | tee logs/host3 | sed -u 's/^/  [host3]  /' &
sleep 1
docker run --name host4 --network "$NETWORK" --ip "$HOST4_IP" -v "$PWD/build/host4.yml:/nebula/host4.yml:ro" --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm "$CONTAINER" -config host4.yml 2>&1 | tee logs/host4 | sed -u 's/^/  [host4]  /' &
sleep 1

# grab tcpdump pcaps for debugging
docker exec lighthouse1 tcpdump -i tun0 -q -w - -U 2>logs/lighthouse1.inside.log >logs/lighthouse1.inside.pcap &
docker exec lighthouse1 tcpdump -i eth0 -q -w - -U 2>logs/lighthouse1.outside.log >logs/lighthouse1.outside.pcap &
docker exec host2 tcpdump -i tun0 -q -w - -U 2>logs/host2.inside.log >logs/host2.inside.pcap &
docker exec host2 tcpdump -i eth0 -q -w - -U 2>logs/host2.outside.log >logs/host2.outside.pcap &
docker exec host3 tcpdump -i tun0 -q -w - -U 2>logs/host3.inside.log >logs/host3.inside.pcap &
docker exec host3 tcpdump -i eth0 -q -w - -U 2>logs/host3.outside.log >logs/host3.outside.pcap &
docker exec host4 tcpdump -i tun0 -q -w - -U 2>logs/host4.inside.log >logs/host4.inside.pcap &
docker exec host4 tcpdump -i eth0 -q -w - -U 2>logs/host4.outside.log >logs/host4.outside.pcap &

docker exec host2 ncat -nklv 0.0.0.0 2000 &
docker exec host3 ncat -nklv 0.0.0.0 2000 &
docker exec host4 ncat -e '/usr/bin/echo helloagainfromhost4' -nkluv 0.0.0.0 4000 &
docker exec host2 ncat -e '/usr/bin/echo host2' -nkluv 0.0.0.0 3000 &
docker exec host3 ncat -e '/usr/bin/echo host3' -nkluv 0.0.0.0 3000 &

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
echo " *** Testing ncat from host2"
echo
set -x
# Should fail because not allowed by host3 inbound firewall
! docker exec host2 ncat -nzv -w5 192.168.100.3 2000 || exit 1
! docker exec host2 ncat -nzuv -w5 192.168.100.3 3000 | grep -q host3 || exit 1

set +x
echo
echo " *** Testing ping from host3"
echo
set -x
docker exec host3 ping -c1 192.168.100.1
docker exec host3 ping -c1 192.168.100.2

set +x
echo
echo " *** Testing ncat from host3"
echo
set -x
docker exec host3 ncat -nzv -w5 192.168.100.2 2000
docker exec host3 ncat -nzuv -w5 192.168.100.2 3000 | grep -q host2

set +x
echo
echo " *** Testing ping from host4"
echo
set -x
docker exec host4 ping -c1 192.168.100.1
# Should fail because not allowed by host4 outbound firewall
! docker exec host4 ping -c1 192.168.100.2 -w5 || exit 1
! docker exec host4 ping -c1 192.168.100.3 -w5 || exit 1

set +x
echo
echo " *** Testing ncat from host4"
echo
set -x
# Should fail because not allowed by host4 outbound firewall
! docker exec host4 ncat -nzv -w5 192.168.100.2 2000 || exit 1
! docker exec host4 ncat -nzv -w5 192.168.100.3 2000 || exit 1
! docker exec host4 ncat -nzuv -w5 192.168.100.2 3000 | grep -q host2 || exit 1
! docker exec host4 ncat -nzuv -w5 192.168.100.3 3000 | grep -q host3 || exit 1

set +x
echo
echo " *** Testing conntrack"
echo
set -x

# host4's outbound firewall only allows ICMP to the lighthouse, so host4
# cannot initiate UDP to host2. Once host2 initiates a flow to host4:4000,
# conntrack must let host4's listener reply on that flow. If it doesn't,
# the echo back from host4 never reaches host2.
docker exec host2 sh -c "(/usr/bin/echo host2; sleep 2) | ncat -nuv 192.168.100.4 4000" | grep -q helloagainfromhost4

docker exec host4 sh -c 'kill 1'
docker exec host3 sh -c 'kill 1'
docker exec host2 sh -c 'kill 1'
docker exec lighthouse1 sh -c 'kill 1'

# Wait up to 30s for all backgrounded jobs to exit rather than relying on a
# fixed sleep.
for _ in $(seq 1 30); do
    [ -z "$(jobs -r)" ] && break
    sleep 1
done

if [ "$(jobs -r)" ]
then
    echo "nebula still running after SIGTERM sent" >&2
    exit 1
fi
