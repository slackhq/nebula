FROM ubuntu:jammy

RUN apt-get update && apt-get install -y iputils-ping ncat tcpdump

ADD ./build /nebula

WORKDIR /nebula

# Optional GODEBUG override baked into the image so smoke.sh's docker run
# invocations don't have to thread an extra env. Used by the FIPS smoke to
# set GODEBUG=fips140=on.
ARG GODEBUG=
ENV GODEBUG=$GODEBUG

ENTRYPOINT ["/nebula/nebula"]
