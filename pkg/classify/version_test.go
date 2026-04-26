package classify

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b     string
		expected int
	}{
		{"1.25.3", "1.25.3", 0},
		{"1.25.9", "1.25.3", 1},
		{"1.25.3", "1.25.9", -1},
		{"1.26.0", "1.25.9", 1},
		{"2.0.0", "1.99.99", 1},
		{"go1.25.9", "go1.25.3", 1},
		{"go1.25.9", "1.25.3", 1},
		{"1.25.9", "go1.25.3", 1},
		{"1.25", "1.25.0", 0},
		{"1.25.0", "1.25", 0},
		{"0.5.0", "0.4.0", 1},
		{"0.4.0", "0.5.0", -1},
		{"0.10.0", "0.9.0", 1},
		{"5.4.0", "5.3.99", 1},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got := CompareVersions(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}
