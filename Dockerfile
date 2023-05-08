FROM golang as builder
WORKDIR /src
COPY . .
RUN make bin-docker

FROM golang as runtime
WORKDIR /config
EXPOSE 4242/udp
COPY --from=builder /src/build/linux-amd64/nebula /app/

VOLUME ["/config"]

ENTRYPOINT ["/app/nebula"]
CMD ["-config", "config.yaml"]
