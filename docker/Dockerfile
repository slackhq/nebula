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

# Run nebula using a wrapper script to setup the tun device
ENTRYPOINT ["/main.sh"]
# Allow users to override the args passed to nebula
CMD ["-config", "/config/config.yml"]
