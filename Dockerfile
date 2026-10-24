# syntax=docker/dockerfile:1

# Build: fetch the pinned fasm2 toolchain (checksum verified) and assemble.
FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f AS build
RUN apk add --no-cache git make
WORKDIR /src
COPY scripts/fetch-fasm2.sh scripts/
RUN ./scripts/fetch-fasm2.sh /opt/fasm2
COPY Makefile ./
COPY src/ src/
RUN make TOOLCHAIN=/opt/fasm2

# Runtime: the static binary and nothing else; no shell, no libc, no package
# manager. Runs as nobody.
FROM scratch
COPY --from=build /src/build/fasm2crud /fasm2crud
USER 65534:65534
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s --start-period=2s --retries=3 \
	CMD ["/fasm2crud", "healthcheck"]
ENTRYPOINT ["/fasm2crud"]
