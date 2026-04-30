FROM golang:1.25-bookworm AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /usr/local/bin/vigil .
RUN go install golang.org/x/vuln/cmd/govulncheck@latest
RUN go install github.com/ankitpokhrel/jira-cli/cmd/jira@latest

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates skopeo curl && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    apt-get purge -y curl && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

COPY certs/ /tmp/rh-certs/
RUN if ls /tmp/rh-certs/*.pem 1>/dev/null 2>&1; then \
        for f in /tmp/rh-certs/*.pem; do cp "$f" "/usr/local/share/ca-certificates/$(basename "$f" .pem).crt"; done && \
        update-ca-certificates; \
    fi && rm -rf /tmp/rh-certs

COPY --from=builder /usr/local/bin/vigil /usr/local/bin/vigil
COPY --from=builder /go/bin/govulncheck /usr/local/bin/govulncheck
COPY --from=builder /go/bin/jira /usr/local/bin/jira
COPY hack/jira-config.yml /etc/vigil/jira-config.yml
COPY hack/entrypoint.sh /usr/local/bin/entrypoint.sh

ENV TRIVY_CACHE_DIR=/tmp/trivy
ENV HOME=/tmp/vigil-home
RUN mkdir -p /tmp/vigil-home && chmod 777 /tmp/vigil-home
USER nobody
WORKDIR /workspace
ENTRYPOINT ["entrypoint.sh"]
