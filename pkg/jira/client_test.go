package jira

import (
	"testing"
)

func TestSplitMultiProjectJQL(t *testing.T) {
	tests := []struct {
		name     string
		jql      string
		expected []string
	}{
		{
			name: "multi-project with ORDER BY",
			jql:  `project in (RHWA, ECOPROJECT) AND issuetype in (Vulnerability, Bug) AND component in ("Fence Agents Remediation") AND status not in (Closed) ORDER BY created DESC`,
			expected: []string{
				`project = RHWA AND issuetype in (Vulnerability, Bug) AND component in ("Fence Agents Remediation") AND status not in (Closed)`,
				`project = ECOPROJECT AND issuetype in (Vulnerability, Bug) AND component in ("Fence Agents Remediation") AND status not in (Closed)`,
			},
		},
		{
			name:     "single project",
			jql:      `project = RHWA AND issuetype = Bug`,
			expected: []string{`project = RHWA AND issuetype = Bug`},
		},
		{
			name: "multi-project no ORDER BY",
			jql:  `project in (RHWA, ECOPROJECT) AND status = Open`,
			expected: []string{
				`project = RHWA AND status = Open`,
				`project = ECOPROJECT AND status = Open`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitMultiProjectJQL(tt.jql)
			if len(got) != len(tt.expected) {
				t.Fatalf("expected %d queries, got %d: %v", len(tt.expected), len(got), got)
			}
			for i, q := range got {
				if q != tt.expected[i] {
					t.Errorf("query[%d]:\n  got:  %s\n  want: %s", i, q, tt.expected[i])
				}
			}
		})
	}
}
