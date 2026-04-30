package fix

import (
	"testing"
)

func TestDirectStrategy_DryRun(t *testing.T) {
	s := &directStrategy{}
	result, err := s.Apply(StrategyOptions{
		Package:    "golang.org/x/net",
		FixVersion: "0.33.0",
		DryRun:     true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Strategy != StrategyDirect {
		t.Errorf("expected direct, got %s", result.Strategy)
	}
	if result.Risk != 1 {
		t.Errorf("expected risk 1, got %d", result.Risk)
	}
	if result.Command != "go get golang.org/x/net@v0.33.0" {
		t.Errorf("unexpected command: %s", result.Command)
	}
}

func TestDirectStrategy_MissingPackage(t *testing.T) {
	s := &directStrategy{}
	_, err := s.Apply(StrategyOptions{DryRun: true})
	if err == nil {
		t.Error("expected error for missing package")
	}
}

func TestReplaceStrategy_DryRun(t *testing.T) {
	s := &replaceStrategy{}
	result, err := s.Apply(StrategyOptions{
		Package:    "golang.org/x/net",
		FixVersion: "0.33.0",
		DryRun:     true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Strategy != StrategyReplace {
		t.Errorf("expected replace, got %s", result.Strategy)
	}
	if result.Risk != 3 {
		t.Errorf("expected risk 3, got %d", result.Risk)
	}
}

func TestMajorStrategy_NotApproved(t *testing.T) {
	s := &majorStrategy{Approved: false}
	_, err := s.Apply(StrategyOptions{
		Package:    "golang.org/x/net",
		FixVersion: "2.0.0",
		DryRun:     true,
	})
	if err == nil {
		t.Error("expected error when not approved")
	}
}

func TestMajorStrategy_Approved_DryRun(t *testing.T) {
	s := &majorStrategy{Approved: true}
	result, err := s.Apply(StrategyOptions{
		Package:    "golang.org/x/net",
		FixVersion: "2.0.0",
		DryRun:     true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Risk != 4 {
		t.Errorf("expected risk 4, got %d", result.Risk)
	}
}

func TestGoMinorStrategy_NotStdlib(t *testing.T) {
	s := &goMinorStrategy{}
	_, err := s.Apply(StrategyOptions{
		Module:     "golang.org/x/net",
		FixVersion: "1.25.9",
		DryRun:     true,
	})
	if err == nil {
		t.Error("expected error for non-stdlib module")
	}
}

func TestParseModGraph(t *testing.T) {
	input := `example.com/app@v0.0.0 golang.org/x/net@v0.30.0
example.com/app@v0.0.0 golang.org/x/text@v0.14.0
golang.org/x/net@v0.30.0 golang.org/x/text@v0.14.0
golang.org/x/net@v0.30.0 golang.org/x/crypto@v0.28.0
`
	graph := parseModGraph(input)

	netParents := graph["golang.org/x/net"]
	if len(netParents) != 1 || stripVersion(netParents[0]) != "example.com/app" {
		t.Errorf("expected golang.org/x/net parent to be example.com/app, got %v", netParents)
	}

	textParents := graph["golang.org/x/text"]
	if len(textParents) != 2 {
		t.Errorf("expected 2 parents for golang.org/x/text, got %d", len(textParents))
	}
}

func TestStripVersion(t *testing.T) {
	if got := stripVersion("golang.org/x/net@v0.30.0"); got != "golang.org/x/net" {
		t.Errorf("expected golang.org/x/net, got %s", got)
	}
	if got := stripVersion("golang.org/x/net"); got != "golang.org/x/net" {
		t.Errorf("expected golang.org/x/net, got %s", got)
	}
}
