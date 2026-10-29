# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jörn Feuerabend

# Packages the release binaries, nothing is compiled here. The build
# context holds linux/amd64/webdavgo, linux/arm64/webdavgo, LICENSE and
# THIRD_PARTY_LICENSES, as extracted from the release archives.

# The final image has no shell, so the data directory and the symlink are
# made here. This stage runs on the build platform: its output is the same
# for every target, and no emulation is needed.
# static-debian13:debug-nonroot
FROM --platform=$BUILDPLATFORM gcr.io/distroless/static-debian13@sha256:c7b8faacc4439b8f5c41ca7ce4a3f8ff3e8520cb0c3444fae7292f687b00d0dd AS layout
USER root
SHELL ["/busybox/sh", "-c"]
# /etc/webdavgo points into the volume, so the default config path
# /etc/webdavgo/webdavgo.conf works for every subcommand without -config.
RUN mkdir -p /out/var/lib/webdavgo /out/etc \
 && chown 65532:65532 /out/var/lib/webdavgo \
 && ln -s /var/lib/webdavgo /out/etc/webdavgo

# static-debian13:nonroot
FROM gcr.io/distroless/static-debian13@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

ARG TARGETPLATFORM
ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.source="https://github.com/joernfeuerabend/webdavgo" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.title="webdavgo" \
      org.opencontainers.image.description="WebDAV file server in a single Go binary, with SEARCH (RFC 5323)"

COPY --from=layout /out/ /
COPY --chmod=0755 ${TARGETPLATFORM}/webdavgo /usr/local/bin/webdavgo
COPY LICENSE THIRD_PARTY_LICENSES /usr/share/doc/webdavgo/

# Selects the config file a new container gets: health listener on, logs
# to stdout. An existing config file is never changed.
ENV WEBDAVGO_CONTAINER=1

USER 65532:65532
# The default data_dir "./data" resolves to /var/lib/webdavgo/data.
WORKDIR /var/lib/webdavgo
VOLUME /var/lib/webdavgo

# 443 WebDAV with TLS and the ACME challenge, 8443 admin UI, 8080 WebDAV
# before a certificate exists.
EXPOSE 443 8443 8080

HEALTHCHECK CMD ["/usr/local/bin/webdavgo", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/webdavgo"]
