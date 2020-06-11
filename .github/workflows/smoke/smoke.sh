#!/bin/sh

set -e -x

docker run --name lighthouse1 --rm nebula:smoke -config lighthouse1.yml -test
docker run --name host2 --rm nebula:smoke -config host2.yml -test
docker run --name host3 --rm nebula:smoke -config host3.yml -test
docker run --name host4 --rm nebula:smoke -config host4.yml -test

docker run --name lighthouse1 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm nebula:smoke -config lighthouse1.yml &
sleep 1
docker run --name host2 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm nebula:smoke -config host2.yml &
sleep 1
docker run --name host3 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm nebula:smoke -config host3.yml &
sleep 1
docker run --name host4 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm nebula:smoke -config host4.yml &
sleep 1

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
docker exec host3 ping -c1 192.168.100.1
docker exec host3 ping -c1 192.168.100.2

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
echo " *** Testing conntrack"
echo
set -x
# host2 can ping host3 now that host3 pinged it first
docker exec host2 ping -c1 192.168.100.3
# host4 can ping host2 once conntrack established
docker exec host2 ping -c1 192.168.100.4
docker exec host4 ping -c1 192.168.100.2
