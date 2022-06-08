#!/bin/bash

set -e -x

set -o pipefail

mkdir -p logs

cleanup() {
    set +e
    if [ "$(jobs -r)" ]
    then
        sudo docker kill lighthouse1 host2 host3 host4
    fi
}

trap cleanup EXIT

sudo docker run --name lighthouse1 --rm nebula:smoke-relay -config lighthouse1.yml -test
sudo docker run --name host2 --rm nebula:smoke-relay -config host2.yml -test
sudo docker run --name host3 --rm nebula:smoke-relay -config host3.yml -test
sudo docker run --name host4 --rm nebula:smoke-relay -config host4.yml -test

sudo docker run --name lighthouse1 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm nebula:smoke-relay -config lighthouse1.yml 2>&1 | tee logs/lighthouse1 | sed 's/^/  [lighthouse1]  /' &
sleep 1
sudo docker run --name host2 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm nebula:smoke-relay -config host2.yml 2>&1 | tee logs/host2 | sed 's/^/  [host2]  /' &
sleep 1
sudo docker run --name host3 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm nebula:smoke-relay -config host3.yml 2>&1 | tee logs/host3 | sed 's/^/  [host3]  /' &
sleep 1
sudo docker run --name host4 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm nebula:smoke-relay -config host4.yml 2>&1 | tee logs/host4 | sed 's/^/  [host4]  /' &
sleep 1

set +x
echo
echo " *** Testing ping from lighthouse1"
echo
set -x
sudo docker exec lighthouse1 ping -c1 192.168.100.2
sudo docker exec lighthouse1 ping -c1 192.168.100.3
sudo docker exec lighthouse1 ping -c1 192.168.100.4

set +x
echo
echo " *** Testing ping from host2"
echo
set -x
sudo docker exec host2 ping -c1 192.168.100.1
# Should fail because no relay configured in this direction
! sudo docker exec host2 ping -c1 192.168.100.3 -w5 || exit 1
! sudo docker exec host2 ping -c1 192.168.100.4 -w5 || exit 1

set +x
echo
echo " *** Testing ping from host3"
echo
set -x
sudo docker exec host3 ping -c1 192.168.100.1
sudo docker exec host3 ping -c1 192.168.100.2
sudo docker exec host3 ping -c1 192.168.100.4

set +x
echo
echo " *** Testing ping from host4"
echo
set -x
sudo docker exec host4 ping -c1 192.168.100.1
# Should fail because relays not allowed
! sudo docker exec host4 ping -c1 192.168.100.2 -w5 || exit 1
sudo docker exec host4 ping -c1 192.168.100.3

sudo docker exec host4 sh -c 'kill 1'
sudo docker exec host3 sh -c 'kill 1'
sudo docker exec host2 sh -c 'kill 1'
sudo docker exec lighthouse1 sh -c 'kill 1'
sleep 1
