# The relay as a container. Packages a binary built outside it: CI builds the
# static musl binary per architecture (the `linux-build` job) and builds this
# with dist/ as the context, holding <arch>/koan-push-relay, the same binaries a
# release attaches. By hand: `docker build -f Dockerfile dist`.

FROM scratch

ARG TARGETARCH

# rustls-platform-verifier needs a system trust store on Linux and does not
# fall back to compiled-in roots; without this, the connection to Apple fails.
# Pinned by digest, so the roots the relay trusts for Apple change only in a
# reviewed commit (Dependabot's docker updates move it).
COPY --from=gcr.io/distroless/static:latest@sha256:4c2cd1dee442c9a99924a378c7c126fac8fef14771579ef567c3f2bdd7a5122a \
     /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY ${TARGETARCH}/koan-push-relay /koan-push-relay

EXPOSE 8080 9090

USER 65532:65532

LABEL org.opencontainers.image.title="koan-push-relay"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/radiosilence/koan-push-relay"

ENTRYPOINT ["/koan-push-relay"]
