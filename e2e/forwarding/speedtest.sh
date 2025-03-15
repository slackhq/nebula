#!/bin/bash

cd "$(dirname "$0")"

if ! test -f ca.key; then
  echo "Generating new test certificates"
  ./generate_certificates.sh
fi

../../nebula -config "$(pwd)/a_config.yml" &>a.out &
A_PID=$!
../../nebula -config "$(pwd)/b_config.yml" &>b.out &
B_PID=$!

iperf3 -s -p 15001 &
IPERF_SERVER_PID=$!

sleep 1
iperf3 -c 127.0.0.1 -p 15002 -P 10 "$@"

# Cleanup
kill $IPERF_SERVER_PID $A_PID $B_PID

# wait for shutdown logs are written to files
sleep 1

echo "##########################################"
echo "A side logs:"
echo "##########################################"
cat a.out

echo "##########################################"
echo "B side logs:"
echo "##########################################"
cat b.out
rm a.out b.out
