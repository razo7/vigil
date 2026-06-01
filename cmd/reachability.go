package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/razo7/vigil/pkg/assess"
	"github.com/razo7/vigil/pkg/discover"
	"github.com/razo7/vigil/pkg/goversion"
	"github.com/razo7/vigil/pkg/reachability"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	reachComponent string
	reachVersion   string
	reachRepoPath  string
	reachFormat    string
	reachGoVersion string
	reachCommit    string
)

var reachabilityCmd = &cobra.Command{
	Use:   "reachability",
	Short: "Run multi-signal reachability analysis on a release branch",
	Long: `Analyze a specific operator release branch for vulnerability reachability
to help decide if a patch release or backport is justified.

Runs govulncheck on the release branch worktree, correlates with OCP
lifecycle data, and produces a verdict for each vulnerability.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if reachComponent == "" {
			return fmt.Errorf("--component is required")
		}
		if reachVersion == "" {
			return fmt.Errorf("--version is required")
		}
		return runReachability()
	},
}

func runReachability() error {
	cfg := getConfig()
	comp, ok := cfg.Components[strings.ToLower(reachComponent)]
	if !ok {
		return fmt.Errorf("unknown component %q", reachComponent)
	}
	operatorName := comp.OperatorName

	repoPath := reachRepoPath
	var repoCleanup func()
	if repoPath == "" {
		var err error
		repoPath, repoCleanup, err = discover.ResolveComponentRepo(reachComponent, loadComponentMap())
		if err != nil {
			return fmt.Errorf("resolving repo for %s: %w", reachComponent, err)
		}
		if repoCleanup != nil {
			defer repoCleanup()
		}
	}

	if reachCommit != "" {
		if err := assess.CheckoutCommit(repoPath, reachCommit); err != nil {
			return fmt.Errorf("pinning to commit: %w", err)
		}
	}

	branch := goversion.ReleaseBranch(reachVersion)

	result, err := reachability.Analyze(repoPath, branch, reachGoVersion, operatorName, reachVersion)
	if err != nil {
		return fmt.Errorf("analyzing %s: %w", branch, err)
	}

	if reachFormat == "html" {
		printReachabilityHTML(result, reachComponent)
	} else {
		printReachabilityTable(result, reachComponent)
	}

	return nil
}

func reachEmoji(label string) string {
	switch label {
	case "REACHABLE":
		return "\xf0\x9f\x8e\xaf REACHABLE"
	case "TEST-ONLY":
		return "\xf0\x9f\xa7\xaa TEST-ONLY"
	case "PACKAGE-LEVEL":
		return "\xf0\x9f\x93\xa6 PACKAGE-LEVEL"
	case "MODULE-LEVEL":
		return "\xf0\x9f\x93\x8b MODULE-LEVEL"
	default:
		return "\xf0\x9f\x9a\xab NOT-IMPORTED"
	}
}

func printReachabilityTable(result *reachability.BranchResult, component string) {
	isTTY := forceColor || term.IsTerminal(int(os.Stdout.Fd()))

	phaseStr := string(result.SupportPhase)
	if result.OCPVersion != "" {
		phaseStr = fmt.Sprintf("OCP %s %s", result.OCPVersion, result.SupportPhase)
	}
	title := fmt.Sprintf(" %s Reachability: %s (Go %s, %s) ",
		strings.ToUpper(component), result.Branch, result.GoVersion, phaseStr)

	type row struct {
		cve, pkg, reach, fixFunc, backport string
	}
	var rows []row
	for _, v := range result.Vulns {
		fixFunc := "no"
		if v.FixFuncMatch {
			fixFunc = "yes"
		}
		backport := "no"
		if v.NeedsBackport {
			backport = "YES"
		}
		rows = append(rows, row{
			cve:      v.CVEID,
			pkg:      shortPackage(v.Package),
			reach:    reachEmoji(v.Reachability),
			fixFunc:  fixFunc,
			backport: backport,
		})
	}

	headers := []string{"CVE", "PACKAGE", "REACH", "FIX-FUNC", "BACKPORT?"}
	cols := make([][]string, len(headers))
	for _, r := range rows {
		cols[0] = append(cols[0], r.cve)
		cols[1] = append(cols[1], r.pkg)
		cols[2] = append(cols[2], r.reach)
		cols[3] = append(cols[3], r.fixFunc)
		cols[4] = append(cols[4], r.backport)
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = displayWidth(h)
		for _, vals := range cols[i] {
			if w := displayWidth(vals); w > widths[i] {
				widths[i] = w
			}
		}
	}

	innerWidth := 0
	for _, w := range widths {
		innerWidth += w
	}
	innerWidth += (len(widths) - 1) * 3

	titleDisplay := displayWidth(title)
	if titleDisplay > innerWidth {
		innerWidth = titleDisplay
	}

	if isTTY {
		fmt.Print("\033[1m")
	}
	fmt.Printf("\xe2\x95\xad%s%s\xe2\x95\xae\n", title, strings.Repeat("\xe2\x94\x80", max(0, innerWidth+2-titleDisplay)))
	if isTTY {
		fmt.Print(colorReset)
	}

	printReachRow(widths, headers, isTTY, true, "")
	fmt.Printf("\xe2\x94\x9c%s\xe2\x94\xa4\n", strings.Repeat("\xe2\x94\x80", innerWidth+2))

	for _, r := range rows {
		reachColor := ""
		if isTTY {
			reachColor = reachColorCode(r.reach)
		}
		vals := []string{r.cve, r.pkg, r.reach, r.fixFunc, r.backport}
		printReachRow(widths, vals, isTTY, false, reachColor)
	}

	needBackport := 0
	for _, v := range result.Vulns {
		if v.NeedsBackport {
			needBackport++
		}
	}
	summary := fmt.Sprintf(" Summary: %d of %d need backport ", needBackport, len(result.Vulns))
	fmt.Printf("\xe2\x94\x9c%s\xe2\x94\xa4\n", strings.Repeat("\xe2\x94\x80", innerWidth+2))
	fmt.Printf("\xe2\x94\x82 %-*s \xe2\x94\x82\n", innerWidth, summary)
	fmt.Printf("\xe2\x95\xb0%s\xe2\x95\xaf\n", strings.Repeat("\xe2\x94\x80", innerWidth+2))
}

func printReachRow(widths []int, vals []string, isTTY, bold bool, reachColor string) {
	fmt.Print("\xe2\x94\x82 ")
	for i, v := range vals {
		pad := widths[i] - displayWidth(v)
		if pad < 0 {
			pad = 0
		}
		if bold && isTTY {
			fmt.Printf("\033[1m%s%s\033[0m", v, strings.Repeat(" ", pad))
		} else if i == 2 && reachColor != "" {
			fmt.Printf("%s%s%s%s", reachColor, v, colorReset, strings.Repeat(" ", pad))
		} else {
			fmt.Printf("%s%s", v, strings.Repeat(" ", pad))
		}
		if i < len(vals)-1 {
			fmt.Print("   ")
		}
	}
	fmt.Print(" \xe2\x94\x82\n")
}

func reachColorCode(reach string) string {
	if strings.Contains(reach, "REACHABLE") {
		return colorHigh
	}
	if strings.Contains(reach, "TEST-ONLY") {
		return colorMed
	}
	if strings.Contains(reach, "PACKAGE-LEVEL") {
		return colorMed
	}
	return colorLow
}

func displayWidth(s string) int {
	w := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r == '\033' {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			if i < len(s) {
				i++
			}
			continue
		}
		if size >= 4 {
			w += 2
		} else {
			w++
		}
	}
	return w
}

func printReachabilityHTML(result *reachability.BranchResult, component string) {
	phaseStr := string(result.SupportPhase)
	if result.OCPVersion != "" {
		phaseStr = fmt.Sprintf("OCP %s %s", result.OCPVersion, result.SupportPhase)
	}

	needBackport := 0
	for _, v := range result.Vulns {
		if v.NeedsBackport {
			needBackport++
		}
	}

	fmt.Printf(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Vigil Reachability: %s %s</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 20px; }
table { border-collapse: collapse; width: 100%%; font-size: 13px; }
th { background: #24292e; color: #fff; padding: 8px 10px; text-align: left; position: sticky; top: 0; }
td { padding: 6px 10px; border-bottom: 1px solid #e1e4e8; }
tr:hover { background: #f6f8fa; }
.tag { padding: 2px 8px; border-radius: 12px; color: #fff; font-size: 12px; font-weight: 600; white-space: nowrap; }
.yes { background: #d32f2f; }
.no { background: #388e3c; }
.reach-reachable { color: #d32f2f; font-weight: bold; }
.reach-test { color: #f57c00; }
.reach-pkg { color: #f57c00; }
.reach-mod { color: #388e3c; }
.reach-none { color: #9e9e9e; }
</style></head><body>
<h1>%s Reachability: %s</h1>
<p>Go %s | %s | Generated: %s</p>
<table><thead><tr>
<th>CVE</th><th>PACKAGE</th><th>REACH</th><th>FIX-FUNC</th><th>BACKPORT?</th>
</tr></thead><tbody>
`, strings.ToUpper(component), result.Branch,
		strings.ToUpper(component), result.Branch,
		result.GoVersion, phaseStr,
		time.Now().Format("2006-01-02 15:04"))

	for _, v := range result.Vulns {
		reachClass := htmlReachClass(v.Reachability)
		reachDisplay := reachEmoji(v.Reachability)

		fixFunc := "no"
		if v.FixFuncMatch {
			fixFunc = "yes"
		}

		backportClass := "no"
		backportLabel := "no"
		if v.NeedsBackport {
			backportClass = "yes"
			backportLabel = "YES"
		}

		fmt.Printf(`<tr><td>%s</td><td>%s</td><td class="%s">%s</td><td>%s</td><td><span class="tag %s">%s</span></td></tr>
`,
			v.CVEID, shortPackage(v.Package), reachClass, reachDisplay, fixFunc, backportClass, backportLabel)
	}

	fmt.Printf(`</tbody></table>
<p><strong>Summary:</strong> %d of %d need backport</p>
</body></html>
`, needBackport, len(result.Vulns))
}

func htmlReachClass(label string) string {
	switch label {
	case "REACHABLE":
		return "reach-reachable"
	case "TEST-ONLY":
		return "reach-test"
	case "PACKAGE-LEVEL":
		return "reach-pkg"
	case "MODULE-LEVEL":
		return "reach-mod"
	default:
		return "reach-none"
	}
}

func init() {
	reachabilityCmd.Flags().StringVar(&reachComponent, "component", "", "Component short name (far, snr, nhc, nmo, mdr)")
	reachabilityCmd.Flags().StringVar(&reachVersion, "version", "", "Operator version (e.g., 0.2, 0.4)")
	reachabilityCmd.Flags().StringVar(&reachRepoPath, "repo-path", "", "Local repo path (clones from GitHub if omitted)")
	reachabilityCmd.Flags().StringVar(&reachFormat, "format", "table", "Output format: table or html")
	reachabilityCmd.Flags().StringVar(&reachGoVersion, "go-version", "", "Downstream Go version override")
	reachabilityCmd.Flags().StringVar(&reachCommit, "commit", "", "Pin repo to a specific commit SHA")
	rootCmd.AddCommand(reachabilityCmd)
}
