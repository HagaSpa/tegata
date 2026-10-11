# syntax=docker/dockerfile:1
# check=error=true

ARG GO_VERSION=1.27-trixie@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build

WORKDIR /app

ARG TARGETARCH

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=bind,target=. \
    CGO_ENABLED=0 GOARCH=$TARGETARCH go build -ldflags="-s" -trimpath -o /bin/tegata .

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 AS final

COPY --from=build /bin/tegata /bin/

WORKDIR /app

ENV TZ=Asia/Tokyo

ENTRYPOINT ["/bin/tegata"]
