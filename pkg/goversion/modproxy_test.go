package goversion

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchModuleGoVersion_ThirdParty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("module golang.org/x/net\n\ngo 1.23.0\n\nrequire (\n\tgolang.org/x/crypto v0.38.0\n)\n"))
	}))
	defer ts.Close()

	old := moduleProxyURL
	moduleProxyURL = ts.URL
	defer func() { moduleProxyURL = old }()

	got, err := FetchModuleGoVersion("golang.org/x/net", "0.40.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "1.23.0" {
		t.Errorf("got %q, want 1.23.0", got)
	}
}

func TestFetchModuleGoVersion_Stdlib(t *testing.T) {
	got, err := FetchModuleGoVersion("stdlib", "1.25.9")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "1.25.9" {
		t.Errorf("got %q, want 1.25.9", got)
	}
}

func TestFetchModuleGoVersion_NoGoDirective(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("module github.com/old/module\n"))
	}))
	defer ts.Close()

	old := moduleProxyURL
	moduleProxyURL = ts.URL
	defer func() { moduleProxyURL = old }()

	got, err := FetchModuleGoVersion("github.com/old/module", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestFetchModuleGoVersion_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	old := moduleProxyURL
	moduleProxyURL = ts.URL
	defer func() { moduleProxyURL = old }()

	_, err := FetchModuleGoVersion("github.com/nonexistent/module", "1.0.0")
	if err == nil {
		t.Error("expected error for 404 response")
	}
}

func TestFetchModuleGoVersion_VersionPrefixed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/golang.org/x/net/@v/v0.33.0.mod" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write([]byte("module golang.org/x/net\n\ngo 1.18\n"))
	}))
	defer ts.Close()

	old := moduleProxyURL
	moduleProxyURL = ts.URL
	defer func() { moduleProxyURL = old }()

	got, err := FetchModuleGoVersion("golang.org/x/net", "v0.33.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "1.18" {
		t.Errorf("got %q, want 1.18", got)
	}
}
