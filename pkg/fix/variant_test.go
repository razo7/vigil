package fix

import (
	"testing"

	"github.com/razo7/vigil/pkg/goversion"
)

func TestIsFixedCVE(t *testing.T) {
	vuln := &goversion.VulnEntry{
		ID:      "GO-2026-4870",
		Aliases: []string{"CVE-2026-32283"},
	}

	if !isFixedCVE(vuln, "CVE-2026-32283") {
		t.Error("should match by alias")
	}
	if !isFixedCVE(vuln, "GO-2026-4870") {
		t.Error("should match by ID")
	}
	if isFixedCVE(vuln, "CVE-9999-99999") {
		t.Error("should not match unrelated CVE")
	}
}

func TestMatchesModule(t *testing.T) {
	vuln := &goversion.VulnEntry{
		Module:  "golang.org/x/net",
		Package: "golang.org/x/net/http2",
	}

	if !matchesModule(vuln, "golang.org/x/net") {
		t.Error("should match exact module")
	}

	vulnSub := &goversion.VulnEntry{
		Module:  "google.golang.org/grpc",
		Package: "google.golang.org/grpc/internal/transport",
	}
	if !matchesModule(vulnSub, "google.golang.org/grpc") {
		t.Error("should match when package has module as prefix")
	}
	if matchesModule(vulnSub, "golang.org/x/net") {
		t.Error("should not match unrelated module")
	}
}

func TestModuleFromPackage(t *testing.T) {
	if moduleFromPackage("crypto/tls") != "stdlib" {
		t.Error("stdlib package should return stdlib")
	}
	if moduleFromPackage("golang.org/x/net") != "golang.org/x/net" {
		t.Error("third-party package should return itself")
	}
}

func TestPrimaryCVEID(t *testing.T) {
	vuln := &goversion.VulnEntry{
		ID:      "GO-2026-4870",
		Aliases: []string{"CVE-2026-32283"},
	}
	if got := primaryCVEID(vuln); got != "CVE-2026-32283" {
		t.Errorf("expected CVE alias, got %q", got)
	}

	vulnNoCVE := &goversion.VulnEntry{
		ID: "GO-2026-4870",
	}
	if got := primaryCVEID(vulnNoCVE); got != "GO-2026-4870" {
		t.Errorf("expected GO ID when no CVE alias, got %q", got)
	}
}
