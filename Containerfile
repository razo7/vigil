FROM golang:1.25-bookworm

RUN apt-get update && apt-get install -y git skopeo && rm -rf /var/lib/apt/lists/*
RUN go install golang.org/x/vuln/cmd/govulncheck@latest

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /usr/local/bin/vigil .

WORKDIR /workspace
ENTRYPOINT ["vigil"]
