FROM ubuntu:jammy

# eMudhra 53119: changing this value busts the layer cache so the refreshed
# ca-certificates package is installed.
ARG CA_CERTIFICATES_REFRESH=2026-10-21
RUN apt-get update && apt-get install -y ca-certificates iputils-ping ncat tcpdump \
    && v="$(dpkg-query -W -f='${Version}' ca-certificates)" \
    && echo "ca-certificates ${v}" \
    && dpkg --compare-versions "$v" ge 20260816ubuntu0.22.04.1 \
    || { echo "ca-certificates ${v:-missing} is older than 20260816ubuntu0.22.04.1 (eMudhra 53119)" >&2; exit 1; }

ADD ./build /nebula

WORKDIR /nebula

ENTRYPOINT ["/nebula/nebula"]
