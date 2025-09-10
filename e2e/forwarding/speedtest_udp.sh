#!/bin/bash

cd "$(dirname "$0")"

./speedtest.sh --udp --bidir --bitrate=100MiB "$@"
