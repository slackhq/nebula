FROM gcr.io/distroless/static:latest

ARG TARGETOS TARGETARCH

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="nebula" \
      org.opencontainers.image.description="A scalable overlay networking tool with a focus on performance, simplicity and security" \
      org.opencontainers.image.vendor="Nebula OSS" \
      org.opencontainers.image.source="https://github.com/slackhq/nebula" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

COPY build/$TARGETOS-$TARGETARCH/nebula /nebula
COPY build/$TARGETOS-$TARGETARCH/nebula-cert /nebula-cert

VOLUME ["/config"]

ENTRYPOINT ["/nebula"]
# Allow users to override the args passed to nebula
CMD ["-config", "/config/config.yml"]
