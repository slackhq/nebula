FROM ubuntu:jammy

RUN apt-get update && apt-get install -y iputils-ping ncat tcpdump

ADD ./build /nebula

WORKDIR /nebula

ENTRYPOINT ["/nebula/nebula"]
