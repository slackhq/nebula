FROM debian:buster
MAINTAINER Michael Gebetsroither <michael@mgeb.org>

# Create the builder, if you have fpm on your system just execute the script below on the host
# Used packages:
#   - make libffi-dev libtool (are needed because of https://github.com/ffi/ffi/issues/611)
#   - curl/wget for downloading
#   - jq for parsing json returned by github api
# /.cpanm is for cpanminus to work as un-named user
RUN set -ex \
    && apt-get update -q \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -q ruby ruby-dev rubygems cpanminus make libffi-dev libtool curl wget jq \
    && gem install --no-ri --no-rdoc fpm \
    && install -d -m 777 /.cpanm

COPY . /build
WORKDIR /build

# execute deb build script, wrapped into docker for portability
RUN set -ex \
    && ./build-deb.sh
