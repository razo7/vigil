package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/razo7/vigil/pkg/types"
	"golang.org/x/term"
)

var (
	jsonKeyRe        = regexp.MustCompile(`^(\s*)"([^"]+)":`)
	jsonStringRe     = regexp.MustCompile(`:\s*"(.*)"(,?)$`)
	jsonNumberRe     = regexp.MustCompile(`:\s*(\d+\.?\d*)(,?)$`)
	jsonBoolRe       = regexp.MustCompile(`:\s*(true|false)(,?)$`)
	jsonNullRe       = regexp.MustCompile(`:\s*(null)(,?)$`)
	jsonBareStringRe = regexp.MustCompile(`^(\s*)"(.*)"(,?)$`)
	ocpTierRe        = regexp.MustCompile(`(Platform Aligned|Rolling Stream)( OCP )([\d., ]+)`)
)

const (
	colorReset    = "\033[0m"
	colorKey      = "\033[36m"   // cyan
	colorString   = "\033[33m"   // yellow
	colorNumber   = "\033[35m"   // magenta
	colorBool     = "\033[34m"   // blue
	colorNull     = "\033[90m"   // gray
	colorBrace    = "\033[37m"   // white
	colorCrit     = "\033[91m"   // bright red
	colorHigh     = "\033[31m"   // red
	colorMed      = "\033[33m"   // yellow
	colorLow      = "\033[32m"   // green
	colorMagBold  = "\033[1;35m" // bold magenta (tier)
	colorCyanBold = "\033[1;36m" // bold cyan (OCP version)
)

func printJSON(v interface{}) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	data := strings.TrimSuffix(buf.String(), "\n")

	if !forceColor && !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Println(data)
		return nil
	}

	fmt.Println(colorizeJSON(data))
	return nil
}

func colorizeJSON(s string) string {
	lines := splitLines(s)
	for i, line := range lines {
		lines[i] = colorizeLine(line)
	}
	return joinLines(lines)
}

func colorizeLine(line string) string {
	if m := jsonKeyRe.FindStringSubmatchIndex(line); m != nil {
		indent := line[m[2]:m[3]]
		key := line[m[4]:m[5]]
		rest := line[m[1]:]

		keyColor := colorKey
		if key == "recommendation" || key == "action" {
			keyColor = "\033[1;97;44m" // bold bright white on blue
		}
		colored := indent + keyColor + `"` + key + `"` + colorReset + ":"

		if sm := jsonStringRe.FindStringSubmatch(line); sm != nil {
			val := sm[1]
			comma := sm[2]
			if key == "action" {
				colored += " " + colorString + `"` + val + `"` + colorReset + comma
				return colored
			}
			colored += " " + colorForValue(key, val) + `"` + val + `"` + colorReset + comma
			return colored
		}
		if sm := jsonNumberRe.FindStringSubmatch(line); sm != nil {
			colored += " " + colorNumber + sm[1] + colorReset + sm[2]
			return colored
		}
		if sm := jsonBoolRe.FindStringSubmatch(line); sm != nil {
			colored += " " + colorBool + sm[1] + colorReset + sm[2]
			return colored
		}
		if sm := jsonNullRe.FindStringSubmatch(line); sm != nil {
			colored += " " + colorNull + sm[1] + colorReset + sm[2]
			return colored
		}

		colored += rest
		return colored
	}

	if sm := jsonBareStringRe.FindStringSubmatch(line); sm != nil {
		indent := sm[1]
		val := sm[2]
		comma := sm[3]
		if ocpTierRe.MatchString(val) {
			return indent + `"` + colorizeOCPSupport(val) + `"` + comma
		}
		if strings.Contains(val, " → ") {
			return indent + `"` + colorizeCallPath(val) + `"` + colorReset + comma
		}
		return indent + colorString + `"` + val + `"` + colorReset + comma
	}

	return colorBrace + line + colorReset
}

func colorForValue(key, val string) string {
	switch key {
	case "severity_label":
		switch val {
		case "CRITICAL":
			return colorCrit
		case "HIGH":
			return colorHigh
		case "MEDIUM":
			return colorMed
		case "LOW":
			return colorLow
		}
	case "priority":
		switch val {
		case "Critical":
			return colorCrit
		case "High":
			return colorHigh
		case "Medium":
			return colorMed
		case "Low":
			return colorLow
		case "Blocked":
			return colorNull
		case "Misassigned":
			return colorNull
		}
	case "classification":
		switch val {
		case "Fixable Now":
			return colorLow
		case "Blocked by Go":
			return colorHigh
		case "Not Reachable":
			return colorLow
		case "Misassigned":
			return colorNull
		case "Not Go":
			return colorMed
		}
	case "reachability":
		if len(val) >= 9 && val[:9] == "REACHABLE" {
			return colorHigh
		}
		return colorLow
	case "due_date":
		return colorForDate(val)
	}
	return colorString
}

func colorizeOCPSupport(val string) string {
	return ocpTierRe.ReplaceAllStringFunc(val, func(match string) string {
		parts := ocpTierRe.FindStringSubmatch(match)
		tier := parts[1]
		sep := parts[2]
		ver := parts[3]
		return colorMagBold + tier + colorReset + sep + colorCyanBold + ver + colorReset
	})
}

func colorizeCallPath(val string) string {
	parts := strings.Split(val, " → ")
	if len(parts) <= 1 {
		return colorString + val
	}
	for i := range parts[:len(parts)-1] {
		parts[i] = colorString + parts[i]
	}
	parts[len(parts)-1] = "\033[1;37m" + parts[len(parts)-1] // bold white for last function
	return strings.Join(parts, colorReset+" → ")
}

func colorForDate(val string) string {
	d, err := time.Parse("2006-01-02", val)
	if err != nil {
		return colorString
	}
	days := int(time.Until(d).Hours() / 24)
	switch {
	case days < 0:
		return colorCrit
	case days <= 7:
		return colorHigh
	case days <= 30:
		return colorMed
	default:
		return colorLow
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func joinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	result := lines[0]
	for _, l := range lines[1:] {
		result += "\n" + l
	}
	return result
}

func printCallTree(cveID string, callPaths []string) {
	if len(callPaths) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\n  Call path for %s:\n", cveID)
	for i, frame := range callPaths {
		indent := strings.Repeat("    ", i)
		connector := "└─ "
		if i == len(callPaths)-1 {
			fmt.Fprintf(os.Stderr, "  %s%s%s  ← 🎯\n", indent, connector, frame)
		} else {
			fmt.Fprintf(os.Stderr, "  %s%s%s\n", indent, connector, frame)
		}
	}
}

func printDashboard(component string, rows []combinedRow, gaps []types.DiscoveredVuln, trivyVulns []types.DiscoveredVuln, errors []string) {
	termWidth, _, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || termWidth < 40 {
		termWidth = 60
	}
	if termWidth > 80 {
		termWidth = 80
	}

	classCounts := map[types.Classification]int{}
	reachCounts := map[string]int{}
	for _, r := range rows {
		classCounts[r.classification]++
		reach := baseReachability(r.reachability)
		reachCounts[reach]++
	}

	var actionItems []combinedRow
	for _, r := range rows {
		if r.classification == types.FixableNow {
			actionItems = append(actionItems, r)
		}
	}
	sort.Slice(actionItems, func(i, j int) bool {
		pi := priorityRank(actionItems[i].priority)
		pj := priorityRank(actionItems[j].priority)
		if pi != pj {
			return pi < pj
		}
		return actionItems[i].cvss > actionItems[j].cvss
	})
	if len(actionItems) > 5 {
		actionItems = actionItems[:5]
	}

	innerWidth := termWidth - 4
	title := fmt.Sprintf(" Vigil Scan: %s ", component)
	titlePad := innerWidth - len(title)
	leftPad := titlePad / 2
	rightPad := titlePad - leftPad
	if leftPad < 0 {
		leftPad = 0
	}
	if rightPad < 0 {
		rightPad = 0
	}

	fmt.Fprintf(os.Stderr, "\n╭─%s%s%s─╮\n", strings.Repeat("─", leftPad), title, strings.Repeat("─", rightPad))
	emitDashLine(innerWidth, "")

	classLabel := "📊 Classification"
	reachLabel := "🎯 Reachability"
	emitDashLine(innerWidth, fmt.Sprintf("  %-*s%s", innerWidth/2, classLabel, reachLabel))

	classLines := []struct {
		icon  string
		label string
		key   types.Classification
	}{
		{"🔴🔧", "Fixable Now", types.FixableNow},
		{"🟢✓ ", "Not Reachable", types.NotReachable},
		{"🐍  ", "Not Go", types.NotGo},
		{"↩️  ", "Misassigned", types.Misassigned},
		{"🟠⏳", "Blocked by Go", types.BlockedByGo},
	}
	reachLines := []struct {
		icon  string
		label string
		key   string
	}{
		{"🎯", "REACHABLE", "REACHABLE"},
		{"🧪", "TEST-ONLY", "TEST-ONLY"},
		{"📦", "PACKAGE-LEVEL", "PACKAGE-LEVEL"},
		{"📋", "MODULE-LEVEL", "MODULE-LEVEL"},
		{"🚫", "NOT-IMPORTED", "NOT-IMPORTED"},
	}

	maxPairLines := len(classLines)
	if len(reachLines) > maxPairLines {
		maxPairLines = len(reachLines)
	}
	for i := 0; i < maxPairLines; i++ {
		leftHalf := ""
		if i < len(classLines) {
			cl := classLines[i]
			leftHalf = fmt.Sprintf("%s %s %d", cl.icon, padRight(string(cl.label), 14), classCounts[cl.key])
		}
		rightHalf := ""
		if i < len(reachLines) {
			rl := reachLines[i]
			rightHalf = fmt.Sprintf("%s %-14s %d", rl.icon, rl.label, reachCounts[rl.key])
		}
		emitDashLine(innerWidth, fmt.Sprintf("  %-*s%s", innerWidth/2, leftHalf, rightHalf))
	}

	if len(actionItems) > 0 {
		emitDashLine(innerWidth, "")
		emitDashLine(innerWidth, "  ⚡ Top Action Items")
		for idx, item := range actionItems {
			prioIcon := priorityIcon(item.priority)
			reachIcon := reachabilityIcon(baseReachability(item.reachability))
			line := fmt.Sprintf("  %d. %s %s %s  %s  %s", idx+1, prioIcon, item.ticket, shortPackage(item.pkg), item.priority, reachIcon)
			if len(line) > innerWidth {
				line = line[:innerWidth]
			}
			emitDashLine(innerWidth, line)
		}
	}

	emitDashLine(innerWidth, "")

	var footerParts []string
	if len(gaps) > 0 {
		footerParts = append(footerParts, fmt.Sprintf("🔍 %d discovered (no ticket)", len(gaps)))
	}
	if len(trivyVulns) > 0 {
		footerParts = append(footerParts, fmt.Sprintf("%d trivy-only", len(trivyVulns)))
	}
	if len(errors) > 0 {
		footerParts = append(footerParts, fmt.Sprintf("⚠️  %d errors", len(errors)))
	}
	if len(footerParts) > 0 {
		emitDashLine(innerWidth, "  "+strings.Join(footerParts, " | "))
	}

	fmt.Fprintf(os.Stderr, "╰─%s─╯\n", strings.Repeat("─", innerWidth))
}

func emitDashLine(innerWidth int, content string) {
	visible := visibleLen(content)
	pad := innerWidth - visible
	if pad < 0 {
		pad = 0
	}
	fmt.Fprintf(os.Stderr, "│ %s%s │\n", content, strings.Repeat(" ", pad))
}

func visibleLen(s string) int {
	n := 0
	inRune := false
	runeBytes := 0
	for _, r := range s {
		if r >= 0x1F000 || (r >= 0x2600 && r <= 0x27BF) || (r >= 0x1F300 && r <= 0x1FAFF) ||
			r == 0xFE0F || r == 0x200D || r == '🎯' || r == '📊' || r == '📦' || r == '📋' ||
			r == '🚫' || r == '🔴' || r == '🟢' || r == '🟠' || r == '🐍' || r == '🔧' ||
			r == '⚡' || r == '🔍' || r == '🧪' || r == '⚠' {
			if !inRune {
				n += 2
				inRune = true
				runeBytes = 0
			}
			runeBytes++
			if runeBytes > 2 {
				inRune = false
			}
			continue
		}
		if r == '↩' || r == '✓' {
			n++
			continue
		}
		inRune = false
		n++
	}
	return n
}

func padRight(s string, width int) string {
	pad := width - len(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

func baseReachability(reach string) string {
	if idx := strings.Index(reach, " ("); idx >= 0 {
		return reach[:idx]
	}
	return reach
}

func priorityRank(p types.Priority) int {
	switch p {
	case types.PriorityCritical:
		return 0
	case types.PriorityHigh:
		return 1
	case types.PriorityMedium:
		return 2
	case types.PriorityLow:
		return 3
	default:
		return 4
	}
}

func priorityIcon(p types.Priority) string {
	switch p {
	case types.PriorityCritical:
		return "🔴"
	case types.PriorityHigh:
		return "🟠"
	case types.PriorityMedium:
		return "🟡"
	case types.PriorityLow:
		return "🟢"
	default:
		return "⚪"
	}
}

func reachabilityIcon(reach string) string {
	switch reach {
	case "REACHABLE":
		return "🎯"
	case "TEST-ONLY":
		return "🧪"
	case "PACKAGE-LEVEL":
		return "📦"
	case "MODULE-LEVEL":
		return "📋"
	case "NOT-IMPORTED":
		return "🚫"
	default:
		return ""
	}
}

func htmlClassColor(c types.Classification) string {
	switch c {
	case types.FixableNow:
		return "#d32f2f"
	case types.BlockedByGo:
		return "#f57c00"
	case types.NotReachable:
		return "#388e3c"
	case types.NotGo:
		return "#fbc02d"
	case types.Misassigned:
		return "#9e9e9e"
	default:
		return "#000"
	}
}

func htmlPrioColor(p types.Priority) string {
	switch p {
	case types.PriorityCritical:
		return "#d32f2f"
	case types.PriorityHigh:
		return "#f57c00"
	case types.PriorityMedium:
		return "#fbc02d"
	case types.PriorityLow:
		return "#388e3c"
	default:
		return "#9e9e9e"
	}
}

func printHTMLTable(results []*types.Result, gaps []types.DiscoveredVuln, disc *types.DiscoverResult, trivyVulns []types.DiscoveredVuln) {
	rows := buildCombinedRows(results, gaps, disc, trivyVulns)

	fmt.Println(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Vigil Scan Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 20px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th { background: #24292e; color: #fff; padding: 8px 10px; text-align: left; position: sticky; top: 0; }
td { padding: 6px 10px; border-bottom: 1px solid #e1e4e8; }
tr:hover { background: #f6f8fa; }
a { color: #0366d6; text-decoration: none; }
a:hover { text-decoration: underline; }
.tag { padding: 2px 8px; border-radius: 12px; color: #fff; font-size: 12px; font-weight: 600; white-space: nowrap; }
</style></head><body>
<h1>Vigil Scan Report</h1>
<p>Generated: ` + time.Now().Format("2006-01-02 15:04") + `</p>
<table><thead><tr>
<th>SRC</th><th>TICKET</th><th>CREATED</th><th>UPDATED</th><th>CVE</th><th>VERSION</th><th>LANG</th><th>STATUS</th><th>CLASSIFICATION</th><th>PRIORITY</th><th>PACKAGE</th><th>CVSS</th><th>REACHABILITY</th>
</tr></thead><tbody>`)

	for _, row := range rows {
		langDisplay := row.lang
		if row.langSrc != "" {
			langDisplay = fmt.Sprintf("%s(%s)", row.lang, row.langSrc)
		}
		pkgDisplay := row.pkg
		if row.pkgSrc != "" && row.pkg != "" {
			pkgDisplay = fmt.Sprintf("%s(%s)", row.pkg, row.pkgSrc)
		}

		ticketCell := row.ticket
		if row.ticketURL != "" {
			ticketCell = fmt.Sprintf(`<a href="%s">%s</a>`, row.ticketURL, row.ticket)
		}
		cveCell := row.cveID
		if row.cveURL != "" {
			cveCell = fmt.Sprintf(`<a href="%s">%s</a>`, row.cveURL, row.cveID)
		}

		classCell := fmt.Sprintf(`<span class="tag" style="background:%s">%s</span>`, htmlClassColor(row.classification), row.classification)
		prioCell := fmt.Sprintf(`<span class="tag" style="background:%s">%s</span>`, htmlPrioColor(row.priority), shortPriority(row.priority))

		reachDisplay := row.reachability
		if ep := entryPointFile(row.callPaths); ep != "" {
			label := row.reachability
			if isTestPath(ep) && label == "REACHABLE" {
				label = "TEST-ONLY"
			}
			reachDisplay = fmt.Sprintf("%s (%s)", label, ep)
		} else if row.reachability == "MODULE-LEVEL" {
			reachDisplay = "MODULE-LEVEL (go.mod only)"
		} else if row.reachability == "PACKAGE-LEVEL" && row.importChain != "" {
			reachDisplay = fmt.Sprintf("PACKAGE-LEVEL (%s)", row.importChain)
		}

		fmt.Printf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%.1f</td><td>%s</td></tr>\n",
			row.src, ticketCell, row.created, row.updated, cveCell, row.version, langDisplay, row.status, classCell, prioCell, pkgDisplay, row.cvss, reachDisplay)
	}

	fmt.Println(`</tbody></table></body></html>`)
}
