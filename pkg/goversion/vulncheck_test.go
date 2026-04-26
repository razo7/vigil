package goversion

import (
	"testing"
)

func TestParseGovulncheckOutput_MultiLineJSON(t *testing.T) {
	input := []byte(`{
  "config": {
    "protocol_version": "v1.0.0",
    "scanner_name": "govulncheck"
  }
}
{
  "osv": {
    "id": "GO-2026-4870",
    "aliases": ["CVE-2026-32283"],
    "affected": [{
      "package": {"name": "crypto/tls", "ecosystem": "Go"},
      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "v1.25.9"}]}]
    }]
  }
}
{
  "finding": {
    "osv": "GO-2026-4870",
    "fixed_version": "v1.25.9",
    "trace": [
      {"module": "stdlib", "version": "v1.25.8"}
    ]
  }
}
{
  "finding": {
    "osv": "GO-2026-4870",
    "fixed_version": "v1.25.9",
    "trace": [
      {"module": "stdlib", "version": "v1.25.8", "package": "crypto/tls"}
    ]
  }
}
{
  "finding": {
    "osv": "GO-2026-4870",
    "fixed_version": "v1.25.9",
    "trace": [
      {"module": "stdlib", "package": "crypto/tls", "function": "HandshakeContext", "receiver": "*Conn", "position": {"filename": "/usr/local/go/src/crypto/tls/conn.go", "line": 166}},
      {"module": "stdlib", "package": "net/http", "function": "Do", "receiver": "*Client", "position": {"filename": "/usr/local/go/src/net/http/client.go", "line": 597}},
      {"module": "example.com/myapp", "package": "example.com/myapp/pkg", "function": "Fetch", "position": {"filename": "/home/user/myapp/pkg/fetch.go", "line": 42}}
    ]
  }
}
`)

	result, err := parseGovulncheckOutput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(result.Vulns))
	}

	vuln := result.Vulns[0]

	if vuln.ID != "GO-2026-4870" {
		t.Errorf("expected ID GO-2026-4870, got %s", vuln.ID)
	}

	if len(vuln.Aliases) != 1 || vuln.Aliases[0] != "CVE-2026-32283" {
		t.Errorf("expected alias CVE-2026-32283, got %v", vuln.Aliases)
	}

	if vuln.Package != "crypto/tls" {
		t.Errorf("expected package crypto/tls, got %s", vuln.Package)
	}

	if !vuln.Reachable {
		t.Error("expected reachable to be true")
	}

	if vuln.ModuleOnly {
		t.Error("expected module_only to be false")
	}

	if vuln.FixVersion != "1.25.9" {
		t.Errorf("expected fix version 1.25.9, got %s", vuln.FixVersion)
	}

	if vuln.CallPath != "*Conn.HandshakeContext (/usr/local/go/src/crypto/tls/conn.go) → *Client.Do (/usr/local/go/src/net/http/client.go) → Fetch (/home/user/myapp/pkg/fetch.go)" {
		t.Errorf("unexpected call path: %s", vuln.CallPath)
	}
}

func TestParseGovulncheckOutput_ModuleLevelOnly(t *testing.T) {
	input := []byte(`{
  "osv": {
    "id": "GO-2025-3488",
    "aliases": ["CVE-2025-22868"],
    "affected": [{
      "package": {"name": "golang.org/x/oauth2", "ecosystem": "Go"},
      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "v0.25.0"}]}]
    }]
  }
}
{
  "finding": {
    "osv": "GO-2025-3488",
    "fixed_version": "v0.25.0",
    "trace": [
      {"module": "golang.org/x/oauth2", "version": "v0.20.0"}
    ]
  }
}
`)

	result, err := parseGovulncheckOutput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(result.Vulns))
	}

	vuln := result.Vulns[0]

	if !vuln.ModuleOnly {
		t.Error("expected module_only to be true")
	}

	if vuln.Reachable {
		t.Error("expected reachable to be false")
	}

	if vuln.Package != "golang.org/x/oauth2" {
		t.Errorf("expected package golang.org/x/oauth2, got %s", vuln.Package)
	}

	if vuln.FixVersion != "0.25.0" {
		t.Errorf("expected fix version 0.25.0, got %s", vuln.FixVersion)
	}
}

func TestParseGovulncheckOutput_PackageLevel(t *testing.T) {
	input := []byte(`{
  "osv": {
    "id": "GO-2024-3333",
    "aliases": ["CVE-2024-45338"],
    "affected": [{
      "package": {"name": "golang.org/x/net", "ecosystem": "Go"},
      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "v0.33.0"}]}]
    }]
  }
}
{
  "finding": {
    "osv": "GO-2024-3333",
    "fixed_version": "v0.33.0",
    "trace": [
      {"module": "golang.org/x/net", "version": "v0.30.0", "package": "golang.org/x/net/html"}
    ]
  }
}
`)

	result, err := parseGovulncheckOutput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	vuln := result.Vulns[0]

	if vuln.Reachable {
		t.Error("expected reachable to be false")
	}

	if vuln.ModuleOnly {
		t.Error("expected module_only to be false (package-level)")
	}

	if vuln.Package != "golang.org/x/net/html" {
		t.Errorf("expected package golang.org/x/net/html, got %s", vuln.Package)
	}
}

func TestParseGovulncheckOutput_EmptyInput(t *testing.T) {
	result, err := parseGovulncheckOutput([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Vulns) != 0 {
		t.Errorf("expected 0 vulns, got %d", len(result.Vulns))
	}
}

func TestParseGovulncheckOutput_MultipleVulns(t *testing.T) {
	input := []byte(`{
  "osv": {
    "id": "GO-2026-4870",
    "aliases": ["CVE-2026-32283"],
    "affected": [{"package": {"name": "crypto/tls", "ecosystem": "Go"}, "ranges": [{"events": [{"fixed": "v1.25.9"}]}]}]
  }
}
{
  "osv": {
    "id": "GO-2025-3488",
    "aliases": ["CVE-2025-22868"],
    "affected": [{"package": {"name": "golang.org/x/oauth2", "ecosystem": "Go"}, "ranges": [{"events": [{"fixed": "v0.25.0"}]}]}]
  }
}
{
  "finding": {
    "osv": "GO-2026-4870",
    "fixed_version": "v1.25.9",
    "trace": [{"module": "stdlib", "package": "crypto/tls", "function": "Read", "receiver": "*Conn"}]
  }
}
{
  "finding": {
    "osv": "GO-2025-3488",
    "fixed_version": "v0.25.0",
    "trace": [{"module": "golang.org/x/oauth2", "version": "v0.20.0"}]
  }
}
`)

	result, err := parseGovulncheckOutput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Vulns) != 2 {
		t.Fatalf("expected 2 vulns, got %d", len(result.Vulns))
	}
}
