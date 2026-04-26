package cve

import (
	"testing"
)

func TestParseCVEResponse_CNA(t *testing.T) {
	input := []byte(`{
  "containers": {
    "cna": {
      "descriptions": [{"lang": "en", "value": "Buffer overflow in Go stdlib"}],
      "metrics": [
        {"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N"}}
      ]
    }
  }
}`)

	info, err := parseCVEResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Score != 7.5 {
		t.Errorf("expected score 7.5, got %f", info.Score)
	}
	if info.Severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %s", info.Severity)
	}
	if info.Description != "Buffer overflow in Go stdlib" {
		t.Errorf("unexpected description: %s", info.Description)
	}
}

func TestParseCVEResponse_ADP(t *testing.T) {
	input := []byte(`{
  "containers": {
    "cna": {
      "descriptions": [{"lang": "en", "value": "TLS issue"}],
      "metrics": []
    },
    "adp": [
      {
        "providerMetadata": {"shortName": "CISA-ADP"},
        "metrics": [
          {"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
        ]
      }
    ]
  }
}`)

	info, err := parseCVEResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Score != 9.8 {
		t.Errorf("expected score 9.8, got %f", info.Score)
	}
	if info.Severity != "CRITICAL" {
		t.Errorf("expected severity CRITICAL, got %s", info.Severity)
	}
	if info.Description != "TLS issue" {
		t.Errorf("unexpected description: %s", info.Description)
	}
}

func TestParseCVEResponse_NoMetrics(t *testing.T) {
	input := []byte(`{
  "containers": {
    "cna": {
      "descriptions": [{"lang": "en", "value": "Some vuln"}]
    }
  }
}`)

	info, err := parseCVEResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Score != 0 {
		t.Errorf("expected score 0, got %f", info.Score)
	}
	if info.Description != "Some vuln" {
		t.Errorf("unexpected description: %s", info.Description)
	}
}

func TestParseCVEResponse_CVSSV4(t *testing.T) {
	input := []byte(`{
  "containers": {
    "cna": {
      "descriptions": [{"lang": "en", "value": "New vuln"}],
      "metrics": [
        {"cvssV4_0": {"baseScore": 8.7, "baseSeverity": "HIGH"}}
      ]
    }
  }
}`)

	info, err := parseCVEResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Score != 8.7 {
		t.Errorf("expected score 8.7, got %f", info.Score)
	}
}
