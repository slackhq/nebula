FROM gcr.io/distroless/static:latest

ARG TARGETPLATFORM
ARG SOURCEDIR

COPY $SOURCEDIR/nebula /nebula
COPY $SOURCEDIR/nebula-cert /nebula-cert

VOLUME ["/config"]

# Run nebula using a wrapper script to setup the tun device
ENTRYPOINT ["/nebula"]
# Allow users to override the args passed to nebula
CMD ["-config", "/config/config.yml"]
