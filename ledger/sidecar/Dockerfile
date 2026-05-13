# syntax=docker/dockerfile:1.7
FROM golang:1.25-alpine AS builder
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ledger-sidecar ./cmd/ledger-sidecar
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ledger-admin   ./cmd/ledger-admin
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ledger-verify  ./cmd/ledger-verify
RUN go test ./internal/ledger/... ./internal/merkle/... ./internal/auth/... ./internal/rewards/...

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/ledger-sidecar /usr/local/bin/ledger-sidecar
COPY --from=builder /out/ledger-admin   /usr/local/bin/ledger-admin
COPY --from=builder /out/ledger-verify  /usr/local/bin/ledger-verify
USER nonroot:nonroot
EXPOSE 18080
ENTRYPOINT ["/usr/local/bin/ledger-sidecar"]
