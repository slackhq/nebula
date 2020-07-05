#############      builder       #############
FROM golang:1.14.4 AS builder

WORKDIR /go/src/github.com/slackhq/nebula

COPY . .

RUN make

# #############      nebula        #############
FROM alpine:3.12.0 AS nebula

RUN apk add --update libc6-compat

COPY --from=builder /go/src/github.com/slackhq/nebula/nebula /nebula
COPY --from=builder /go/src/github.com/slackhq/nebula/nebula-cert /nebula-cert

WORKDIR /

ENTRYPOINT ["/nebula"]