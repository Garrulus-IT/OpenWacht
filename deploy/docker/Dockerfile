# SPDX-License-Identifier: AGPL-3.0-only
#
# Image der Zentrale (1.0.14). Kontext ist dist/docker aus
#   go run ./tools/build -ziele alle -docker
# (dort liegen diese Datei, die Zentrale je Architektur und die Downloads).
#
#   docker build -t openwacht-zentrale:<version> dist/docker
#   docker buildx build --platform linux/amd64,linux/arm64 -t … dist/docker
#
# Das Image ist leer bis auf die Zentrale, die Downloads, die
# CA-Zertifikate und die Zeitzonen; es läuft ohne root (65532).

FROM debian:13-slim AS basis
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*

FROM scratch
ARG TARGETARCH
COPY --from=basis /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=basis /usr/share/zoneinfo /usr/share/zoneinfo
COPY passwd group /etc/
COPY --chmod=0755 openwacht-zentrale_linux_${TARGETARCH} /usr/bin/openwacht-zentrale
COPY downloads /usr/share/openwacht/downloads
COPY --chown=65532:65532 --chmod=0700 leer /var/lib/openwacht
COPY --chmod=1777 leer /tmp
ENV OPENWACHT_DATEN=/var/lib/openwacht HOME=/var/lib/openwacht TZ=Europe/Berlin
VOLUME /var/lib/openwacht
USER 65532:65532
EXPOSE 8443 8444
ENTRYPOINT ["/usr/bin/openwacht-zentrale"]
CMD ["dienst"]
