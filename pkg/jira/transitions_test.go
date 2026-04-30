package jira

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetTransitions(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/rest/api/3/issue/TEST-1/transitions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		resp := map[string]interface{}{
			"transitions": []map[string]interface{}{
				{"id": "11", "name": "To Do"},
				{"id": "21", "name": "In Progress"},
				{"id": "31", "name": "Done"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	c := &Client{baseURL: ts.URL, authHeader: "Basic dGVzdA==", httpClient: ts.Client()}
	transitions, err := c.GetTransitions("TEST-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(transitions) != 3 {
		t.Fatalf("expected 3 transitions, got %d", len(transitions))
	}
	if transitions[1].Name != "In Progress" {
		t.Errorf("transition[1].Name = %q, want %q", transitions[1].Name, "In Progress")
	}
}

func TestTransitionTicket(t *testing.T) {
	var postedTransitionID string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			resp := map[string]interface{}{
				"transitions": []map[string]interface{}{
					{"id": "11", "name": "To Do"},
					{"id": "21", "name": "In Progress"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		if r.Method == "POST" {
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			tr := body["transition"].(map[string]interface{})
			postedTransitionID = tr["id"].(string)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	c := &Client{baseURL: ts.URL, authHeader: "Basic dGVzdA==", httpClient: ts.Client()}
	err := c.TransitionTicket("TEST-1", "In Progress")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if postedTransitionID != "21" {
		t.Errorf("posted transition ID = %q, want %q", postedTransitionID, "21")
	}
}

func TestTransitionTicketNotFound(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"transitions": []map[string]interface{}{
				{"id": "11", "name": "To Do"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	c := &Client{baseURL: ts.URL, authHeader: "Basic dGVzdA==", httpClient: ts.Client()}
	err := c.TransitionTicket("TEST-1", "Closed")
	if err == nil {
		t.Fatal("expected error for missing transition")
	}
}

func TestLinkPR(t *testing.T) {
	var receivedURL string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		obj := body["object"].(map[string]interface{})
		receivedURL = obj["url"].(string)
		w.WriteHeader(http.StatusCreated)
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	c := &Client{baseURL: ts.URL, authHeader: "Basic dGVzdA==", httpClient: ts.Client()}
	err := c.LinkPR("TEST-1", "https://github.com/org/repo/pull/42", "Fix CVE-2026-1234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedURL != "https://github.com/org/repo/pull/42" {
		t.Errorf("linked URL = %q, want PR URL", receivedURL)
	}
}

func TestAddLabel(t *testing.T) {
	var receivedLabels []map[string]string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		update := body["update"].(map[string]interface{})
		labels := update["labels"].([]interface{})
		for _, l := range labels {
			lm := l.(map[string]interface{})
			receivedLabels = append(receivedLabels, map[string]string{"add": lm["add"].(string)})
		}
		w.WriteHeader(http.StatusNoContent)
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	c := &Client{baseURL: ts.URL, authHeader: "Basic dGVzdA==", httpClient: ts.Client()}
	err := c.AddLabel("TEST-1", "vigil-assessed", "cve-fixable")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(receivedLabels) != 2 {
		t.Fatalf("expected 2 labels, got %d", len(receivedLabels))
	}
	if receivedLabels[0]["add"] != "vigil-assessed" {
		t.Errorf("label[0] = %q, want vigil-assessed", receivedLabels[0]["add"])
	}
}
