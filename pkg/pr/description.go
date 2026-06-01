package pr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/razo7/vigil/pkg/argus"
)

const skillExcerptMaxLen = 500

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

func FormatDescriptionWithValidation(opts Options, steps []ValidationStep, securityWarnings []string) string {
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

	if len(securityWarnings) > 0 {
		b.WriteString("\n## Security review\n\n")
		for _, warning := range securityWarnings {
			fmt.Fprintf(&b, "- :warning: %s\n", warning)
		}
	}

	skillNames := argus.MatchSkills([]string{opts.CVEID, opts.Package})
	if len(skillNames) > 0 {
		cacheDir := defaultCacheDir()
		fetched, _ := argus.FetchSkills(skillNames, cacheDir)

		b.WriteString("\n## ARGUS skills\n\n")
		for _, skill := range fetched {
			excerpt := firstParagraph(skill.Content, skillExcerptMaxLen)
			if excerpt != "" {
				fmt.Fprintf(&b, "### %s\n\n%s\n\n", skill.Name, excerpt)
			} else {
				fmt.Fprintf(&b, "- %s\n", skill.Name)
			}
		}

		fetchedNames := make(map[string]bool, len(fetched))
		for _, s := range fetched {
			fetchedNames[s.Name] = true
		}
		for _, name := range skillNames {
			if !fetchedNames[name] {
				fmt.Fprintf(&b, "- %s *(content unavailable)*\n", name)
			}
		}
	}

	return b.String()
}

func firstParagraph(content string, maxLen int) string {
	content = strings.TrimSpace(content)
	if content == "" {
		return ""
	}

	lines := strings.SplitN(content, "\n", -1)
	var para strings.Builder
	started := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			if started {
				break
			}
			continue
		}
		if trimmed == "" {
			if started {
				break
			}
			continue
		}
		if started {
			para.WriteByte(' ')
		}
		para.WriteString(trimmed)
		started = true
	}

	text := para.String()
	if len(text) > maxLen {
		cut := strings.LastIndexByte(text[:maxLen], ' ')
		if cut < maxLen/2 {
			cut = maxLen
		}
		text = text[:cut] + "..."
	}
	return text
}

func defaultCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cache", "vigil")
}
