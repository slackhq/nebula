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
        sudo docker kill lighthouse1 host2 host3 host4
    fi
}

trap cleanup EXIT

CONTAINER="nebula:${NAME:-smoke}"

sudo docker run --name lighthouse1 --rm "$CONTAINER" -config lighthouse1.yml -test
sudo docker run --name host2 --rm "$CONTAINER" -config host2.yml -test
sudo docker run --name host3 --rm "$CONTAINER" -config host3.yml -test
sudo docker run --name host4 --rm "$CONTAINER" -config host4.yml -test

sudo docker run --name lighthouse1 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm "$CONTAINER" -config lighthouse1.yml 2>&1 | tee logs/lighthouse1 | sed -u 's/^/  [lighthouse1]  /' &
sleep 1
sudo docker run --name host2 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm "$CONTAINER" -config host2.yml 2>&1 | tee logs/host2 | sed -u 's/^/  [host2]  /' &
sleep 1
sudo docker run --name host3 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm "$CONTAINER" -config host3.yml 2>&1 | tee logs/host3 | sed -u 's/^/  [host3]  /' &
sleep 1
sudo docker run --name host4 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm "$CONTAINER" -config host4.yml 2>&1 | tee logs/host4 | sed -u 's/^/  [host4]  /' &
sleep 1

set +x
echo
echo " *** Testing ping from lighthouse1"
echo
set -x
sudo docker exec lighthouse1 ping -c1 192.168.100.2
sudo docker exec lighthouse1 ping -c1 192.168.100.3

set +x
echo
echo " *** Testing ping from host2"
echo
set -x
sudo docker exec host2 ping -c1 192.168.100.1
# Should fail because not allowed by host3 inbound firewall
! sudo docker exec host2 ping -c1 192.168.100.3 -w5 || exit 1

set +x
echo
echo " *** Testing ping from host3"
echo
set -x
sudo docker exec host3 ping -c1 192.168.100.1
sudo docker exec host3 ping -c1 192.168.100.2

set +x
echo
echo " *** Testing ping from host4"
echo
set -x
sudo docker exec host4 ping -c1 192.168.100.1
# Should fail because not allowed by host4 outbound firewall
! sudo docker exec host4 ping -c1 192.168.100.2 -w5 || exit 1
! sudo docker exec host4 ping -c1 192.168.100.3 -w5 || exit 1

set +x
echo
echo " *** Testing conntrack"
echo
set -x
# host2 can ping host3 now that host3 pinged it first
sudo docker exec host2 ping -c1 192.168.100.3
# host4 can ping host2 once conntrack established
sudo docker exec host2 ping -c1 192.168.100.4
sudo docker exec host4 ping -c1 192.168.100.2

sudo docker exec host4 sh -c 'kill 1'
sudo docker exec host3 sh -c 'kill 1'
sudo docker exec host2 sh -c 'kill 1'
sudo docker exec lighthouse1 sh -c 'kill 1'
sleep 1

if [ "$(jobs -r)" ]
then
    echo "nebula still running after SIGTERM sent" >&2
    exit 1
fi
