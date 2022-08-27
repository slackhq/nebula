FROM golang as builder
WORKDIR /src
COPY . .
RUN make bin-docker

FROM golang as runtime
WORKDIR /app
EXPOSE 4242
COPY --from=builder /src/build/linux-amd64/nebula /app/

VOLUME ["/config"]

ENTRYPOINT ["./nebula", "-config", "/config/config.yaml"]