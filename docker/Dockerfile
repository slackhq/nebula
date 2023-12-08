FROM alpine:latest

ARG TARGETPLATFORM
RUN echo "Building image for $TARGETPLATFORM"

COPY release/$TARGETPLATFORM/nebula /usr/local/bin/nebula
RUN chmod +x /usr/local/bin/nebula

COPY docker/main.sh /main.sh
RUN chmod +x /main.sh

VOLUME ["/config"]

CMD ["/main.sh"]
