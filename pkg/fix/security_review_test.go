package fix

import (
	"testing"
)

func TestParseRequireLine(t *testing.T) {
	tests := []struct {
		input    string
		wantMod  string
		wantVer  string
	}{
		{"	golang.org/x/net v0.33.0", "golang.org/x/net", "v0.33.0"},
		{"golang.org/x/net v0.33.0 // indirect", "golang.org/x/net", "v0.33.0"},
		{"require (", "", ""},
		{")", "", ""},
		{"", "", ""},
	}

	for _, tt := range tests {
		result := parseRequireLine(tt.input)
		if result[0] != tt.wantMod {
			t.Errorf("parseRequireLine(%q) module = %q, want %q", tt.input, result[0], tt.wantMod)
		}
		if result[1] != tt.wantVer {
			t.Errorf("parseRequireLine(%q) version = %q, want %q", tt.input, result[1], tt.wantVer)
		}
	}
}

func TestIsDowngrade(t *testing.T) {
	tests := []struct {
		oldVer string
		newVer string
		want   bool
	}{
		{"v0.33.0", "v0.32.0", true},
		{"v0.33.0", "v0.34.0", false},
		{"v0.33.0", "v0.33.0", false},
		{"v1.0.0", "v0.99.0", true},
		{"v2.0.0", "v1.0.0", true},
		{"v0.33.0", "v0.33.1", false},
		{"v0.33.1", "v0.33.0", true},
	}

	for _, tt := range tests {
		got := isDowngrade(tt.oldVer, tt.newVer)
		if got != tt.want {
			t.Errorf("isDowngrade(%q, %q) = %v, want %v", tt.oldVer, tt.newVer, got, tt.want)
		}
	}
}

func TestCheckVersionDowngrades(t *testing.T) {
	diff := `-	golang.org/x/net v0.33.0
+	golang.org/x/net v0.32.0
`
	warnings := checkVersionDowngrades(diff)
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(warnings))
	}
	if warnings[0] != "potential version downgrade: golang.org/x/net v0.33.0 -> v0.32.0" {
		t.Errorf("unexpected warning: %s", warnings[0])
	}
}

func TestCheckVersionDowngrades_Upgrade(t *testing.T) {
	diff := `-	golang.org/x/net v0.32.0
+	golang.org/x/net v0.33.0
`
	warnings := checkVersionDowngrades(diff)
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for upgrade, got %v", warnings)
	}
}

func TestCheckNewDependencies(t *testing.T) {
	diff := `+	example.com/newpkg v1.0.0
-	golang.org/x/net v0.32.0
+	golang.org/x/net v0.33.0
`
	warnings := checkNewDependencies(diff)
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if warnings[0] != "new dependency added: example.com/newpkg v1.0.0" {
		t.Errorf("unexpected warning: %s", warnings[0])
	}
}

func TestCheckNewDependencies_NoNew(t *testing.T) {
	diff := `-	golang.org/x/net v0.32.0
+	golang.org/x/net v0.33.0
`
	warnings := checkNewDependencies(diff)
	if len(warnings) != 0 {
		t.Errorf("expected no warnings when only upgrading, got %v", warnings)
	}
}

func TestCheckRemovedSecurityImports(t *testing.T) {
	diff := `-	"crypto/tls"
+	"net/http"
`
	warnings := checkRemovedSecurityImports(diff)
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(warnings))
	}
}

func TestCheckRemovedSecurityImports_NoRemoval(t *testing.T) {
	diff := `-	"net/http"
+	"net/http"
`
	warnings := checkRemovedSecurityImports(diff)
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}
}

func TestStripPrerelease(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1", "1"},
		{"1-rc1", "1"},
		{"0", "0"},
	}
	for _, tt := range tests {
		if got := stripPrerelease(tt.input); got != tt.want {
			t.Errorf("stripPrerelease(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
