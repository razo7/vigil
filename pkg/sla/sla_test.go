package sla

import (
	"testing"
	"time"
)

func TestDependentDueDays(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{"CRITICAL", 20},
		{"critical", 20},
		{"HIGH", 50},
		{"IMPORTANT", 50},
		{"Important", 50},
		{"MEDIUM", 80},
		{"MODERATE", 80},
		{"Moderate", 80},
		{"LOW", 180},
		{"low", 180},
		{"UNKNOWN", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := DependentDueDays(tt.severity)
		if got != tt.want {
			t.Errorf("DependentDueDays(%q) = %d, want %d", tt.severity, got, tt.want)
		}
	}
}

func TestCalculateDueDate(t *testing.T) {
	created := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC) // Monday

	t.Run("critical", func(t *testing.T) {
		due := CalculateDueDate(created, "CRITICAL", false)
		want := created.AddDate(0, 0, 20) // Jan 25
		if !due.Equal(want) {
			t.Errorf("got %v, want %v", due, want)
		}
	})

	t.Run("unknown severity returns zero", func(t *testing.T) {
		due := CalculateDueDate(created, "UNKNOWN", false)
		if !due.IsZero() {
			t.Errorf("expected zero time for unknown severity, got %v", due)
		}
	})

	t.Run("kev overrides severity", func(t *testing.T) {
		due := CalculateDueDate(created, "LOW", true)
		// 7 business days from Monday Jan 5 = next Monday+1 Jan 14 (skipping 2 weekends)
		// Mon5→Tue6(1)→Wed7(2)→Thu8(3)→Fri9(4)→Mon12(5)→Tue13(6)→Wed14(7)
		want := time.Date(2026, 1, 14, 12, 0, 0, 0, time.UTC)
		if !due.Equal(want) {
			t.Errorf("KEV due: got %v, want %v", due, want)
		}
	})
}

func TestStatus(t *testing.T) {
	now := time.Now()

	t.Run("overdue", func(t *testing.T) {
		status, days := Status(now.AddDate(0, 0, -5))
		if status != StatusOverdue {
			t.Errorf("expected Overdue, got %q", status)
		}
		if days >= 0 {
			t.Errorf("expected negative days, got %d", days)
		}
	})

	t.Run("approaching", func(t *testing.T) {
		status, days := Status(now.AddDate(0, 0, 3))
		if status != StatusApproaching {
			t.Errorf("expected Approaching, got %q", status)
		}
		if days <= 0 || days > 7 {
			t.Errorf("expected 1-7 days, got %d", days)
		}
	})

	t.Run("on track", func(t *testing.T) {
		status, days := Status(now.AddDate(0, 0, 30))
		if status != StatusOnTrack {
			t.Errorf("expected On Track, got %q", status)
		}
		if days <= 7 {
			t.Errorf("expected >7 days, got %d", days)
		}
	})

	t.Run("zero time", func(t *testing.T) {
		status, _ := Status(time.Time{})
		if status != "" {
			t.Errorf("expected empty status for zero time, got %q", status)
		}
	})
}

func TestIsKEV(t *testing.T) {
	tests := []struct {
		labels []string
		want   bool
	}{
		{[]string{"kev"}, true},
		{[]string{"KEV"}, true},
		{[]string{"known-exploited-vulnerability"}, true},
		{[]string{"major-incident"}, true},
		{[]string{"security", "compliance"}, false},
		{nil, false},
		{[]string{}, false},
	}
	for _, tt := range tests {
		got := IsKEV(tt.labels)
		if got != tt.want {
			t.Errorf("IsKEV(%v) = %v, want %v", tt.labels, got, tt.want)
		}
	}
}

func TestAddBusinessDays(t *testing.T) {
	monday := time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC)

	t.Run("5 business days from monday", func(t *testing.T) {
		got := addBusinessDays(monday, 5)
		want := time.Date(2026, 1, 12, 9, 0, 0, 0, time.UTC) // next Monday
		if !got.Equal(want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	friday := time.Date(2026, 1, 9, 9, 0, 0, 0, time.UTC)
	t.Run("1 business day from friday", func(t *testing.T) {
		got := addBusinessDays(friday, 1)
		want := time.Date(2026, 1, 12, 9, 0, 0, 0, time.UTC) // Monday
		if !got.Equal(want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}
