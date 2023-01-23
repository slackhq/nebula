#!/bin/bash

export VAGRANT_CWD="$PWD/vagrant-$1"

set -e -x

cleanup() {
    set +e
    if [ "$(jobs -r)" ]
    then
        sudo docker kill lighthouse1 host2
    fi
    vagrant destroy -f
}

trap cleanup EXIT

sudo docker run --name lighthouse1 --rm nebula:smoke -config lighthouse1.yml -test
sudo docker run --name host2 --rm nebula:smoke -config host2.yml -test

vagrant up
vagrant ssh -c "cd /nebula && /nebula/$1-nebula -config host3.yml -test"

sudo docker run --name lighthouse1 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm nebula:smoke -config lighthouse1.yml &
sleep 1
sudo docker run --name host2 --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN --rm nebula:smoke -config host2.yml &
sleep 1
vagrant ssh -c "cd /nebula && sudo sh -c 'echo \$\$ >/nebula/pid && exec /nebula/$1-nebula -config host3.yml'" &
sleep 15

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
vagrant ssh -c "ping -c1 192.168.100.1"
vagrant ssh -c "ping -c1 192.168.100.2"

sleep 1

vagrant ssh -c "sudo xargs kill </nebula/pid"
sleep 1
sudo docker exec host2 sh -c 'kill 1'
sleep 1
sudo docker exec lighthouse1 sh -c 'kill 1'
sleep 1
