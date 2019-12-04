#############      builder       #############
FROM golang:1.13.4 AS builder

WORKDIR /go/src/github.com/slackhq/nebula

COPY . .

RUN make

# #############      nebula        #############
FROM alpine:3.10.3 AS nebula

RUN apk add --update libc6-compat

COPY --from=builder /go/src/github.com/slackhq/nebula/nebula /nebula
COPY --from=builder /go/src/github.com/slackhq/nebula/nebula-cert /nebula-cert

WORKDIR /

ENTRYPOINT ["/nebula"]