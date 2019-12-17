#!/bin/sh

set -e -x

rm -rf ./build
mkdir ./build

(
    cd build

    cp ../../../../nebula .
    cp ../../../../nebula-cert .
    cp ../*.yml .

    ./nebula-cert ca -name "Smoke Test"
    ./nebula-cert sign -name "lighthouse1" -ip "192.168.100.1/24"
    ./nebula-cert sign -name "host2" -ip "192.168.100.2/24"
    ./nebula-cert sign -name "host3" -ip "192.168.100.3/24"
)

docker build -t nebula:smoke .
