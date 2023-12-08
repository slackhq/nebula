FROM alpine:latest

ARG TARGETPLATFORM
ARG SOURCEDIR
RUN echo "Building image for $TARGETPLATFORM"

COPY $SOURCEDIR/nebula /usr/local/bin/nebula
COPY $SOURCEDIR/nebula-cert /usr/local/bin/nebula-cert

RUN chmod +x /usr/local/bin/nebula && \
    chmod +x /usr/local/bin/nebula-cert

COPY docker/main.sh /main.sh
RUN chmod +x /main.sh

VOLUME ["/config"]

CMD ["/main.sh"]
