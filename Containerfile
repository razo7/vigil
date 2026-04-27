FROM golang:1.25-bookworm AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /usr/local/bin/vigil .
RUN go install golang.org/x/vuln/cmd/govulncheck@latest

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates skopeo && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/vigil /usr/local/bin/vigil
COPY --from=builder /root/go/bin/govulncheck /usr/local/bin/govulncheck

USER nobody
WORKDIR /workspace
ENTRYPOINT ["vigil"]
