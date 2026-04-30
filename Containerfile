FROM golang:1.25-bookworm AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /usr/local/bin/vigil .
RUN go install golang.org/x/vuln/cmd/govulncheck@latest
RUN go install github.com/ankitpokhrel/jira-cli/cmd/jira@latest

# Strip Go toolchain to ~120MB (from ~500MB) for the runtime image.
# govulncheck needs `go list` (bin/go + pkg/tool/compile) and stdlib
# source (src/) for reachability analysis, but not cmd source, tests,
# API compat data, or tools like cgo/cover/link.
RUN rm -rf /usr/local/go/doc /usr/local/go/api /usr/local/go/src/cmd \
    && find /usr/local/go/src -name '*_test.go' -delete \
    && find /usr/local/go/src -name 'testdata' -type d -exec rm -rf {} + 2>/dev/null; true \
    && rm -f /usr/local/go/pkg/tool/*/cover \
             /usr/local/go/pkg/tool/*/cgo \
             /usr/local/go/pkg/tool/*/preprofile \
             /usr/local/go/pkg/tool/*/asm \
             /usr/local/go/pkg/tool/*/link

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates skopeo curl && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    apt-get purge -y curl && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

COPY certs/*.pem /usr/local/share/ca-certificates/
RUN for f in /usr/local/share/ca-certificates/*.pem; do \
        mv "$f" "${f%.pem}.crt"; \
    done && update-ca-certificates

COPY --from=builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH=/tmp/go
ENV GOMODCACHE=/tmp/go/mod

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
