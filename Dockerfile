#############      builder       #############
FROM golang:1.16.0 AS builder

WORKDIR /go/src/github.com/slackhq/nebula

COPY . .

RUN make bin

# #############      nebula        #############
FROM alpine:3.13.2 AS nebula

RUN apk add --update libc6-compat

COPY --from=builder /go/src/github.com/slackhq/nebula/nebula /nebula
COPY --from=builder /go/src/github.com/slackhq/nebula/nebula-cert /nebula-cert
COPY entrypoint.sh /entrypoint.sh

WORKDIR /

ENTRYPOINT ["/entrypoint.sh"]