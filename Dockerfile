FROM golang:alpine as buildenv

RUN mkdir -p /build/bin
ADD . /build/
WORKDIR /build
RUN apk add make
RUN make
RUN make install

FROM alpine:3.7
COPY --from=buildenv /build/nebula /usr/bin/nebula
COPY --from=buildenv /build/nebula-cert /usr/bin/nebula-cert
WORKDIR /app
CMD ["nebula"]