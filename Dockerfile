# The relay as a container. Packages a binary built outside it: CI builds the
# static musl binary per architecture (the `linux-build` job) and builds this
# with dist/ as the context, holding <arch>/koan-push-relay, the same binaries a
# release attaches. By hand: `docker build -f Dockerfile dist`.

FROM scratch

ARG TARGETARCH

# rustls-platform-verifier needs a system trust store on Linux and does not
# fall back to compiled-in roots; without this, the connection to Apple fails.
COPY --from=gcr.io/distroless/static:latest \
     /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY ${TARGETARCH}/koan-push-relay /koan-push-relay

EXPOSE 8080 9090

USER 65532:65532

LABEL org.opencontainers.image.title="koan-push-relay"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/radiosilence/koan-push-relay"

ENTRYPOINT ["/koan-push-relay"]
