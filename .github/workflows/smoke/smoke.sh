#!/bin/bash

set -e -x

set -o pipefail

mkdir -p logs

cleanup() {
    echo
    echo " *** cleanup"
    echo

    set +e
    if [ "$(jobs -r)" ]
    then
        docker kill lighthouse1 host2 host3 host4
    fi
}

trap cleanup EXIT

CONTAINER="nebula:${NAME:-smoke}"

docker run --name lighthouse1 --rm "$CONTAINER" -config lighthouse1.yml -test
docker run --name host2 --rm "$CONTAINER" -config host2.yml -test
docker run --name host3 --rm "$CONTAINER" -config host3.yml -test
docker run --name host4 --rm "$CONTAINER" -config host4.yml -test

docker run --name lighthouse1 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm "$CONTAINER" -config lighthouse1.yml 2>&1 | tee logs/lighthouse1 | sed -u 's/^/  [lighthouse1]  /' &
sleep 1
docker run --name host2 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm "$CONTAINER" -config host2.yml 2>&1 | tee logs/host2 | sed -u 's/^/  [host2]  /' &
sleep 1
docker run --name host3 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm "$CONTAINER" -config host3.yml 2>&1 | tee logs/host3 | sed -u 's/^/  [host3]  /' &
sleep 1
docker run --name host4 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm "$CONTAINER" -config host4.yml 2>&1 | tee logs/host4 | sed -u 's/^/  [host4]  /' &
sleep 1

# grab tcpdump pcaps for debugging
docker exec lighthouse1 tcpdump -i nebula1 -q -w - -U 2>logs/lighthouse1.inside.log >logs/lighthouse1.inside.pcap &
docker exec lighthouse1 tcpdump -i eth0 -q -w - -U 2>logs/lighthouse1.outside.log >logs/lighthouse1.outside.pcap &
docker exec host2 tcpdump -i nebula1 -q -w - -U 2>logs/host2.inside.log >logs/host2.inside.pcap &
docker exec host2 tcpdump -i eth0 -q -w - -U 2>logs/host2.outside.log >logs/host2.outside.pcap &
docker exec host3 tcpdump -i nebula1 -q -w - -U 2>logs/host3.inside.log >logs/host3.inside.pcap &
docker exec host3 tcpdump -i eth0 -q -w - -U 2>logs/host3.outside.log >logs/host3.outside.pcap &
docker exec host4 tcpdump -i nebula1 -q -w - -U 2>logs/host4.inside.log >logs/host4.inside.pcap &
docker exec host4 tcpdump -i eth0 -q -w - -U 2>logs/host4.outside.log >logs/host4.outside.pcap &

docker exec host2 ncat -nklv 0.0.0.0 2000 &
docker exec host3 ncat -nklv 0.0.0.0 2000 &
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
# host2 can ping host3 now that host3 pinged it first
docker exec host2 ping -c1 192.168.100.3
# host4 can ping host2 once conntrack established
docker exec host2 ping -c1 192.168.100.4
docker exec host4 ping -c1 192.168.100.2

docker exec host4 sh -c 'kill 1'
docker exec host3 sh -c 'kill 1'
docker exec host2 sh -c 'kill 1'
docker exec lighthouse1 sh -c 'kill 1'
sleep 5

if [ "$(jobs -r)" ]
then
    echo "nebula still running after SIGTERM sent" >&2
    exit 1
fi
