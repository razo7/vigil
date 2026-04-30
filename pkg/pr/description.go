package pr

import (
	"fmt"
	"strings"

	"github.com/razo7/vigil/pkg/argus"
)

type ValidationStep struct {
	Name   string
	Passed bool
}

func FormatDescription(opts Options) string {
	var b strings.Builder

	b.WriteString("## Summary\n\n")
	fmt.Fprintf(&b, "Automated dependency bump to fix **%s**.\n\n", opts.CVEID)
	fmt.Fprintf(&b, "- **Package:** `%s`\n", opts.Package)
	fmt.Fprintf(&b, "- **Fix version:** `%s`\n", opts.FixVersion)
	fmt.Fprintf(&b, "- **Strategy:** %s (risk %d)\n", opts.Strategy, opts.Risk)
	if opts.TicketID != "" {
		fmt.Fprintf(&b, "- **Ticket:** %s\n", opts.TicketID)
	}

	b.WriteString("\n## Test plan\n\n")
	b.WriteString("- [ ] CI passes\n")
	b.WriteString("- [ ] govulncheck confirms CVE is resolved\n")
	b.WriteString("- [ ] No regressions in dependent packages\n")

	return b.String()
}

func FormatDescriptionWithValidation(opts Options, steps []ValidationStep) string {
	var b strings.Builder

	b.WriteString(FormatDescription(opts))

	if len(steps) > 0 {
		b.WriteString("\n## Validation results\n\n")
		for _, step := range steps {
			status := "PASS"
			if !step.Passed {
				status = "FAIL"
			}
			fmt.Fprintf(&b, "- [%s] %s\n", status, step.Name)
		}
	}

	skills := argus.MatchSkills([]string{opts.CVEID, opts.Package})
	if len(skills) > 0 {
		b.WriteString("\n## ARGUS skills\n\n")
		for _, skill := range skills {
			fmt.Fprintf(&b, "- %s\n", skill)
		}
	}

	return b.String()
}
