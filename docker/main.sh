#!/bin/sh
set -euo pipefail

# Create the tun device so it doesn't need to be mounted
mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
    chmod 600 /dev/net/tun
fi

nebula -config /config/config.yml
