#!/bin/bash
# Build slackhq/nebula debian packages
#
# Author: Michael Gebetsroither <michael@mgeb.org>
# This script is published under MIT License

set -e

# override via environment if you want to change it
VERSION_=${VERSION:-'1.1.0'}   # maybe some tag works too?
HASH_=${HASH:-'d558403d52d39a725c66362cb3e1fc45adf07adcd740d902db12acfca00dae4d'}

# no need to configure this for now (only if you want to build for other archs)
NAME_='nebula-linux-amd64.tar.gz'

# jq
#   .assets[]   ... extract all assets
#   select(..   ... pipe through "grep" and select all where "name" element matches
#   .browser..  ... extract element .browser_download_url
url_=$(curl -sL https://api.github.com/repos/slackhq/nebula/releases/latest | \
    jq -r ".assets[] |select(.name|test(\"$NAME_\")) |.browser_download_url")
echo "$HASH_  $NAME_" >shasum
if shasum --strict --check -a 512256 shasum; then
    echo "# Checksum matches, using already downloaded file: $NAME_"
else
    echo '# Checksum does not match, re-downloading'
    wget --no-verbose "$url_"
    echo "$HASH_  $NAME_" >shasum
    echo '# Checksum validation'
    shasum --strict --check -a 512256 shasum
fi

echo '# Building...'
mkdir -p ../out
fpm $@ -s tar -t deb --name nebula --package ../out \
    --url "https://github.com/slackhq/nebula" \
    --description "A scalable overlay networking tool with a focus on performance, simplicity and security" \
    --maintainer "Michael Gebetsroither <michael@mgeb.org>" \
    --vendor "" \
    --version $VERSION_ \
    --deb-systemd nebula.service \
    --prefix /usr/sbin \
    $NAME_
