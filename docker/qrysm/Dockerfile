# syntax=docker/dockerfile:1

ARG QRYSM_REPOSITORY=https://github.com/cyyber/qrysm.git
ARG QRYSM_COMMIT=b53fd7c488f3f0d1d4163b270afac1749eed954b

FROM golang:1.26.5-bookworm AS builder

ARG QRYSM_REPOSITORY
ARG QRYSM_COMMIT

RUN git init /qrysm \
    && git -C /qrysm remote add origin "${QRYSM_REPOSITORY}" \
    && git -C /qrysm fetch --depth 1 origin "${QRYSM_COMMIT}" \
    && git -C /qrysm checkout --detach FETCH_HEAD

WORKDIR /qrysm

RUN GOTOOLCHAIN=local CGO_ENABLED=1 go build \
    -mod=readonly \
    -trimpath \
    -buildvcs=false \
    -o /out/beacon-chain \
    ./cmd/beacon-chain \
    && GOTOOLCHAIN=local CGO_ENABLED=1 go build \
    -mod=readonly \
    -trimpath \
    -buildvcs=false \
    -o /out/validator \
    ./cmd/validator

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/beacon-chain /beacon-chain
COPY --from=builder /out/validator /validator

FROM runtime AS beacon-chain

ARG QRYSM_COMMIT
LABEL org.opencontainers.image.revision="${QRYSM_COMMIT}"

ENTRYPOINT ["/beacon-chain"]

FROM runtime AS validator

ARG QRYSM_COMMIT
LABEL org.opencontainers.image.revision="${QRYSM_COMMIT}"

ENTRYPOINT ["/validator"]
