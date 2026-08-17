# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG REFRACT_VERSION=1.11.0

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X github.com/T-Matrix/Refract/internal/gateway.Version=$REFRACT_VERSION" -o /out/refract ./cmd/gateway

FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S gateway \
    && adduser -S -G gateway gateway \
    && mkdir -p /data \
    && chown gateway:gateway /data \
    && chmod 0700 /data

COPY --from=builder /out/refract /usr/local/bin/refract

USER gateway
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/refract"]
