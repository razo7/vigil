package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
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
		case "Unknown":
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

func htmlClassColor(c types.Classification) string {
	switch c {
	case types.FixableNow:
		return "#d32f2f"
	case types.BlockedByGo:
		return "#f57c00"
	case types.NotReachable:
		return "#388e3c"
	case types.Unknown:
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

func printHTMLTable(results []*types.Result, gaps []types.DiscoveredVuln, disc *types.DiscoverResult, trivyVulns []types.DiscoveredVuln, verbose ...bool) {
	_ = verbose
	rows := buildCombinedRows(results, gaps, disc, trivyVulns)

	cveVersions := map[string][]string{}
	latestVersion := ""
	for _, r := range rows {
		if r.version != "" {
			cveVersions[r.cveID] = append(cveVersions[r.cveID], r.version)
			if latestVersion == "" || compareVersionStrings(r.version, latestVersion) > 0 {
				latestVersion = r.version
			}
		}
	}
	for _, r := range rows {
		if r.ticket == "-- none --" {
			cveVersions[r.cveID] = append(cveVersions[r.cveID], "main")
		}
	}

	classCounts := map[types.Classification]int{}
	prioCounts := map[string]int{}
	for _, r := range rows {
		classCounts[r.classification]++
		prioCounts[string(shortPriority(r.priority))]++
	}

	uniqueVersions := collectUniqueVersions(rows)

	fmt.Printf(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Vigil Scan Report</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;margin:20px;color:#24292e}
.cards{display:flex;flex-wrap:wrap;gap:16px;margin:16px 0}
.card{background:#fff;border:1px solid #e1e4e8;border-radius:8px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.1);flex:1;min-width:280px}
.card h3{margin:0 0 12px;font-size:14px;color:#586069}
table{border-collapse:collapse;width:100%%;font-size:13px;margin-top:16px}
th{background:#24292e;color:#fff;padding:8px 10px;text-align:left;position:sticky;top:0;cursor:pointer}
th:hover{background:#3a3f47}
td{padding:6px 10px;border-bottom:1px solid #e1e4e8}
tr:hover{background:#f6f8fa}
tr:nth-child(even){background:#fafbfc}
tr:nth-child(even):hover{background:#f0f3f6}
a{color:#0366d6;text-decoration:none}
a:hover{text-decoration:underline}
.tag{padding:2px 8px;border-radius:12px;color:#fff;font-size:12px;font-weight:600;white-space:nowrap;display:inline-block}
.severity-bar{height:24px;border-radius:4px;overflow:hidden;display:flex;margin:8px 0}
.severity-bar div{height:100%%;display:flex;align-items:center;justify-content:center;color:#fff;font-size:11px;font-weight:600}
.legend{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px;font-size:12px}
.legend-item{display:flex;align-items:center;gap:4px}
.legend-dot{width:10px;height:10px;border-radius:50%%}
.filter-bar{margin:12px 0;display:flex;flex-wrap:wrap;gap:8px;align-items:center;font-size:13px}
.filter-bar label{font-weight:600;color:#586069}
.filter-bar select{padding:4px 8px;border-radius:4px;border:1px solid #d1d5da}
.mermaid{margin:8px 0 16px;padding:16px;background:#f6f8fa;border-radius:6px;font-size:14px;overflow-x:auto}
.mermaid svg{min-height:150px}
details{margin-top:4px}
details .mermaid{width:max-content;min-width:100%%;padding:20px}
.mermaid-actions{display:flex;gap:8px;align-items:center;margin-top:4px}
.fullview-btn{background:#0366d6;color:#fff;border:none;border-radius:4px;padding:4px 12px;cursor:pointer;font-size:12px;font-weight:600}
.fullview-btn:hover{background:#0256b9}
.mermaid-modal{display:none;position:fixed;top:0;left:0;width:100%%;height:100%%;background:rgba(0,0,0,0.85);z-index:1000;padding:20px;overflow:auto}
.mermaid-modal.active{display:flex;align-items:center;justify-content:center}
.mermaid-modal .mermaid-modal-content{background:#fff;padding:32px;border-radius:12px;width:95%%;max-height:90vh;overflow:auto}
.mermaid-modal .mermaid-modal-content .mermaid{min-width:100%%;font-size:16px}
.mermaid-modal .mermaid-modal-content .mermaid svg{min-width:100%%;min-height:400px}
.mermaid-modal .close{position:absolute;top:16px;right:24px;color:#fff;font-size:32px;cursor:pointer}
.version-tabs{display:flex;gap:0;margin:16px 0 0;border-bottom:2px solid #e1e4e8}
.version-tab{padding:8px 16px;cursor:pointer;border:1px solid transparent;border-bottom:none;border-radius:6px 6px 0 0;font-size:13px;font-weight:600;color:#586069;background:#f6f8fa}
.version-tab:hover{background:#e1e4e8}
.version-tab.active{background:#fff;color:#24292e;border-color:#e1e4e8;margin-bottom:-2px;border-bottom:2px solid #fff}
.action-list{list-style:none;padding:0;margin:0}
.action-list li{padding:6px 0;border-bottom:1px solid #f0f0f0;font-size:13px}
@media print{th{position:static}tr:nth-child(even){background:#fafbfc !important}.mermaid-modal{display:none !important}}
</style></head><body>
<h1>Vigil Scan Report</h1>
<p>Generated: %s</p>
`, time.Now().Format("2006-01-02 15:04"))

	total := len(rows)
	fmt.Println(`<div class="cards">`)

	printHTMLDonutChart(classCounts, total)
	printHTMLSeverityBar(prioCounts, total)
	printHTMLActionItems(rows)

	fmt.Println(`</div>`)

	printHTMLFilterBar(uniqueVersions)

	printHTMLVersionTabs(uniqueVersions)

	fmt.Println(`<table id="scanTable"><thead><tr>
<th onclick="sortTable(0)">SRC</th><th onclick="sortTable(1)">TICKET</th><th onclick="sortTable(2)">CREATED</th><th onclick="sortTable(3)">UPDATED</th><th onclick="sortTable(4)">DUE</th><th onclick="sortTable(5)">CVE</th><th onclick="sortTable(6)">VERSION</th><th onclick="sortTable(7)">ACTION</th><th onclick="sortTable(8)">PRIORITY</th><th onclick="sortTable(9)">PACKAGE</th><th onclick="sortTable(10)">CVSS</th><th onclick="sortTable(11)">REACHABILITY</th>
</tr></thead><tbody>`)

	for _, row := range rows {
		printHTMLTableRow(row, latestVersion, cveVersions)
	}

	fmt.Println(`</tbody></table>`)

	fmt.Println(`<div id="mermaidModal" class="mermaid-modal" onclick="closeMermaidModal(event)">`)
	fmt.Println(`<span class="close" onclick="closeMermaidModal(event)">&times;</span>`)
	fmt.Println(`<div class="mermaid-modal-content" id="mermaidModalBody"></div>`)
	fmt.Println(`</div>`)

	printHTMLScripts()

	fmt.Println(`</body></html>`)
}

func collectUniqueVersions(rows []combinedRow) []string {
	seen := map[string]bool{}
	var versions []string
	for _, r := range rows {
		v := r.version
		if v == "" {
			v = "main"
		}
		if !seen[v] {
			seen[v] = true
			versions = append(versions, v)
		}
	}
	return versions
}

func printHTMLDonutChart(classCounts map[types.Classification]int, total int) {
	fmt.Println(`<div class="card"><h3>Classification Breakdown</h3>`)
	if total > 0 {
		type slice struct {
			label string
			count int
			color string
		}
		slices := []slice{
			{"Fixable Now", classCounts[types.FixableNow], "#d32f2f"},
			{"Not Reachable", classCounts[types.NotReachable], "#388e3c"},
			{"Blocked by Go", classCounts[types.BlockedByGo], "#f57c00"},
			{"Unknown", classCounts[types.Unknown], "#fbc02d"},
			{"Misassigned", classCounts[types.Misassigned], "#9e9e9e"},
		}
		fmt.Println(`<svg viewBox="0 0 200 200" width="180" height="180">`)
		startAngle := -90.0
		for _, s := range slices {
			if s.count == 0 {
				continue
			}
			pct := float64(s.count) / float64(total)
			endAngle := startAngle + pct*360
			x1 := 100 + 80*cosD(startAngle)
			y1 := 100 + 80*sinD(startAngle)
			x2 := 100 + 80*cosD(endAngle)
			y2 := 100 + 80*sinD(endAngle)
			large := 0
			if pct > 0.5 {
				large = 1
			}
			fmt.Printf(`<path d="M100,100 L%.1f,%.1f A80,80 0 %d,1 %.1f,%.1f Z" fill="%s"/>%s`,
				x1, y1, large, x2, y2, s.color, "\n")
			startAngle = endAngle
		}
		fmt.Println(`<circle cx="100" cy="100" r="45" fill="#fff"/>`)
		fmt.Printf(`<text x="100" y="105" text-anchor="middle" font-size="22" font-weight="bold">%d</text>%s`, total, "\n")
		fmt.Println(`</svg>`)
		fmt.Println(`<div class="legend">`)
		for _, s := range slices {
			if s.count == 0 {
				continue
			}
			fmt.Printf(`<span class="legend-item"><span class="legend-dot" style="background:%s"></span>%s (%d)</span>%s`,
				s.color, s.label, s.count, "\n")
		}
		fmt.Println(`</div>`)
	}
	fmt.Println(`</div>`)
}

func printHTMLSeverityBar(prioCounts map[string]int, total int) {
	fmt.Println(`<div class="card"><h3>Severity Distribution</h3>`)
	fmt.Println(`<div class="severity-bar">`)
	type sevSlice struct {
		label string
		count int
		color string
	}
	sevs := []sevSlice{
		{"Critical", prioCounts["Critical"], "#d32f2f"},
		{"High", prioCounts["High"], "#f57c00"},
		{"Medium", prioCounts["Medium"], "#fbc02d"},
		{"Low", prioCounts["Low"], "#388e3c"},
	}
	for _, s := range sevs {
		if s.count == 0 {
			continue
		}
		pct := float64(s.count) / float64(total) * 100
		fmt.Printf(`<div style="width:%.0f%%;background:%s">%s %d</div>%s`, pct, s.color, s.label, s.count, "\n")
	}
	fmt.Println(`</div></div>`)
}

func printHTMLActionItems(rows []combinedRow) {
	fmt.Println(`<div class="card"><h3>Top Action Items</h3><ol class="action-list">`)
	actionCount := 0
	for _, row := range rows {
		if row.classification != types.FixableNow || actionCount >= 10 {
			continue
		}
		actionCount++
		label := row.ticket
		if label == "-- none --" {
			label = row.cveID
		}
		if row.ticketURL != "" {
			label = fmt.Sprintf(`<a href="%s">%s</a>`, row.ticketURL, label)
		} else if row.cveURL != "" {
			label = fmt.Sprintf(`<a href="%s">%s</a>`, row.cveURL, label)
		}
		fmt.Printf("<li>%s <span class=\"tag\" style=\"background:%s\">%s</span> %s %s</li>\n",
			label, htmlPrioColor(row.priority), shortPriority(row.priority), row.pkg, row.reachability)
	}
	fmt.Println(`</ol></div>`)
}

func printHTMLFilterBar(versions []string) {
	fmt.Println(`<div class="filter-bar">`)
	fmt.Println(`<label>Action:</label><select id="actionFilter" onchange="filterTable()">
<option value="">All</option>
<option value="Fix on">Fix</option>
<option value="Blocked">Blocked</option>
<option value="No action">No action</option>
<option value="Manual review">Manual review</option>
<option value="EOL">EOL</option>
<option value="Misassigned">Misassigned</option>
</select>`)
	fmt.Println(`<label>Priority:</label><select id="prioFilter" onchange="filterTable()">
<option value="">All</option>
<option value="Critical">Critical</option>
<option value="High">High</option>
<option value="Medium">Medium</option>
<option value="Low">Low</option>
</select>`)
	if len(versions) > 1 {
		fmt.Println(`<label>Version:</label><select id="verFilter" onchange="filterTable()">`)
		fmt.Println(`<option value="">All</option>`)
		for _, v := range versions {
			fmt.Printf("<option value=\"%s\">%s</option>\n", v, v)
		}
		fmt.Println(`</select>`)
	}
	fmt.Println(`</div>`)
}

func printHTMLVersionTabs(versions []string) {
	if len(versions) <= 1 {
		return
	}
	fmt.Println(`<div class="version-tabs">`)
	fmt.Println(`<span class="version-tab active" onclick="selectVersionTab(this,'')" data-version="">All</span>`)
	for _, v := range versions {
		fmt.Printf(`<span class="version-tab" onclick="selectVersionTab(this,'%s')" data-version="%s">%s</span>%s`, v, v, v, "\n")
	}
	fmt.Println(`</div>`)
}

func printHTMLTableRow(row combinedRow, latestVersion string, cveVersions map[string][]string) {
	srcDisplay := fmt.Sprintf("%s (%s)", row.src, row.lang)
	pkgDisplay := row.pkg
	if row.pkgSrc != "" && row.pkg != "" {
		pkgDisplay = fmt.Sprintf("%s(%s)", row.pkg, row.pkgSrc)
	}

	ticketDisplay := row.ticket
	if row.status != "" && row.status != "No ticket" {
		ticketDisplay = fmt.Sprintf("%s (%s)", row.ticket, row.status)
	}
	ticketCell := ticketDisplay
	if row.ticketURL != "" {
		ticketCell = fmt.Sprintf(`<a href="%s">%s</a>`, row.ticketURL, ticketDisplay)
	}

	cveCell := row.cveID
	if row.cveURL != "" {
		cveCell = fmt.Sprintf(`<a href="%s">%s</a>`, row.cveURL, row.cveID)
	}
	actionCell := htmlAction(row, latestVersion, cveVersions)
	prioCell := fmt.Sprintf(`<span class="tag" style="background:%s">%s</span>`, htmlPrioColor(row.priority), shortPriority(row.priority))

	reachDisplay := buildReachDisplay(row)
	reachCell := buildReachCell(row, reachDisplay)

	dueCell := row.slaDueDate
	if row.slaStatus != "" {
		dueColor := htmlSLAColor(row.slaStatus)
		dueCell = fmt.Sprintf(`<span class="tag" style="background:%s">%s</span>`, dueColor, row.slaDueDate)
	}

	versionAttr := row.version
	if versionAttr == "" {
		versionAttr = "main"
	}

	fmt.Printf(`<tr id="%s" data-version="%s"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td style="white-space:normal;word-break:break-word;max-width:220px">%s</td><td>%s</td><td>%s</td><td>%.1f</td><td>%s</td></tr>`,
		row.ticket, versionAttr, srcDisplay, ticketCell, row.created, row.updated, dueCell, cveCell, row.version, actionCell, prioCell, pkgDisplay, row.cvss, reachCell)
	fmt.Println()
}

func buildReachDisplay(row combinedRow) string {
	if ep := entryPointFile(row.callPaths); ep != "" {
		label := row.reachability
		if isTestPath(ep) && label == "REACHABLE" {
			label = "TEST-ONLY"
		}
		return fmt.Sprintf("%s (%s)", label, ep)
	}
	if row.reachability == "MODULE-LEVEL" {
		return "MODULE-LEVEL (go.mod only)"
	}
	if row.reachability == "PACKAGE-LEVEL" && row.importChain != "" {
		return fmt.Sprintf("PACKAGE-LEVEL (%s)", row.importChain)
	}
	return row.reachability
}

func buildReachCell(row combinedRow, reachDisplay string) string {
	if row.reachability == "PACKAGE-LEVEL" && row.importChain != "" && len(row.callPaths) == 0 {
		return buildImportChainMermaid(row, reachDisplay)
	}

	hasCallPaths := (strings.HasPrefix(row.reachability, "REACHABLE") || strings.HasPrefix(row.reachability, "PACKAGE-LEVEL")) &&
		len(row.callPaths) > 0
	if !hasCallPaths {
		return reachDisplay
	}

	return buildCallPathMermaid(row, reachDisplay)
}

func buildImportChainMermaid(row combinedRow, reachDisplay string) string {
	frames := strings.Split(row.importChain, " → ")
	if len(frames) <= 1 {
		return reachDisplay
	}

	var mermaid strings.Builder
	mermaid.WriteString("graph LR\n")
	for i, frame := range frames {
		safeFrame := strings.ReplaceAll(frame, `"`, "'")
		nodeID := fmt.Sprintf("N%d", i)
		if i < len(frames)-1 {
			nextID := fmt.Sprintf("N%d", i+1)
			fmt.Fprintf(&mermaid, "    %s[\"%s\"] --> %s\n", nodeID, safeFrame, nextID)
		} else {
			fmt.Fprintf(&mermaid, "    %s[\"%s\"]\n", nodeID, safeFrame)
			fmt.Fprintf(&mermaid, "    style %s fill:#f57c00,color:#fff\n", nodeID)
		}
		mermaid.WriteString(mermaidClickDirective(nodeID, frame, true))
	}

	return fmt.Sprintf(`%s<div class="mermaid-actions"><details><summary>📦 import chain</summary><div class="mermaid" data-original="%s">%s</div></details>`+
		`<button class="fullview-btn" onclick="openMermaidModal(this)">🔍 Full view</button></div>`,
		reachDisplay, strings.ReplaceAll(mermaid.String(), `"`, `&quot;`), mermaid.String())
}

func buildCallPathMermaid(row combinedRow, reachDisplay string) string {
	var frames []string
	for _, cp := range row.callPaths {
		parts := strings.Split(cp, " → ")
		frames = append(frames, parts...)
	}
	if len(frames) == 0 {
		return reachDisplay
	}
	if len(frames) > 10 {
		frames = append(frames[:3], append([]string{"..."}, frames[len(frames)-3:]...)...)
	}
	if len(frames) <= 1 {
		return reachDisplay
	}

	var mermaid strings.Builder
	mermaid.WriteString("graph LR\n")
	for i, frame := range frames {
		safeFrame := strings.ReplaceAll(frame, `"`, "'")
		nodeID := fmt.Sprintf("N%d", i)
		if i < len(frames)-1 {
			nextID := fmt.Sprintf("N%d", i+1)
			fmt.Fprintf(&mermaid, "    %s[\"%s\"] --> %s\n", nodeID, safeFrame, nextID)
		} else {
			fmt.Fprintf(&mermaid, "    %s[\"%s\"]\n", nodeID, safeFrame)
			fmt.Fprintf(&mermaid, "    style %s fill:#d32f2f,color:#fff\n", nodeID)
		}
		mermaid.WriteString(mermaidClickDirective(nodeID, frame, false))
	}

	return fmt.Sprintf(`%s<div class="mermaid-actions"><details><summary>🔎 call path</summary><div class="mermaid" data-original="%s">%s</div></details>`+
		`<button class="fullview-btn" onclick="openMermaidModal(this)">🔍 Full view</button></div>`,
		reachDisplay, strings.ReplaceAll(mermaid.String(), `"`, `&quot;`), mermaid.String())
}

var mermaidFileRe = regexp.MustCompile(`\(([^)]+\.go(?::\d+)?)\)`)

func mermaidClickDirective(nodeID, frame string, isImportChain bool) string {
	if isImportChain {
		return mermaidClickForModule(nodeID, frame)
	}
	return mermaidClickForCallPath(nodeID, frame)
}

func mermaidClickForModule(nodeID, mod string) string {
	mod = strings.TrimSpace(mod)
	if mod == "" || mod == "..." {
		return ""
	}
	if strings.HasPrefix(mod, "github.com/") || strings.HasPrefix(mod, "sigs.k8s.io/") || strings.HasPrefix(mod, "k8s.io/") {
		return fmt.Sprintf("    click %s \"https://pkg.go.dev/%s\" _blank\n", nodeID, mod)
	}
	if strings.HasPrefix(mod, "golang.org/") || strings.HasPrefix(mod, "google.golang.org/") {
		return fmt.Sprintf("    click %s \"https://pkg.go.dev/%s\" _blank\n", nodeID, mod)
	}
	if !strings.Contains(mod, "/") && !strings.Contains(mod, ".") {
		return ""
	}
	if strings.Contains(mod, ".") && strings.Contains(mod, "/") {
		return fmt.Sprintf("    click %s \"https://pkg.go.dev/%s\" _blank\n", nodeID, mod)
	}
	return ""
}

func mermaidClickForCallPath(nodeID, frame string) string {
	match := mermaidFileRe.FindStringSubmatch(frame)
	if match == nil {
		return ""
	}
	fileLoc := match[1]
	filePath, lineNum := splitFileLine(fileLoc)

	if strings.HasPrefix(filePath, "src/") {
		goPath := strings.TrimPrefix(filePath, "src/")
		link := fmt.Sprintf("https://cs.opensource.google/go/go/+/refs/tags/go1.26.3:%s", goPath)
		if lineNum != "" {
			link += ";l=" + lineNum
		}
		return fmt.Sprintf("    click %s \"%s\" _blank\n", nodeID, link)
	}

	key := strings.ToLower(scanComponent)
	cfg, hasRepo := getConfig().Components[key]
	repoURL := ""
	if hasRepo && cfg.Repo != "" {
		repoURL = "https://" + cfg.Repo
	}
	if repoURL == "" {
		return ""
	}

	lineAnchor := ""
	if lineNum != "" {
		lineAnchor = "#L" + lineNum
	}

	if strings.HasPrefix(filePath, "vendor/") ||
		strings.HasPrefix(filePath, "pkg/") || strings.HasPrefix(filePath, "cmd/") ||
		strings.HasPrefix(filePath, "internal/") || strings.HasPrefix(filePath, "test/") ||
		strings.HasPrefix(filePath, "e2e/") || strings.HasPrefix(filePath, "api/") {
		return fmt.Sprintf("    click %s \"%s/blob/main/%s%s\" _blank\n", nodeID, repoURL, filePath, lineAnchor)
	}

	if isVendoredPath(filePath) {
		return fmt.Sprintf("    click %s \"%s/blob/main/vendor/%s%s\" _blank\n", nodeID, repoURL, filePath, lineAnchor)
	}

	return ""
}

func splitFileLine(s string) (string, string) {
	if i := strings.LastIndex(s, ":"); i > 0 && i < len(s)-1 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

func isVendoredPath(filename string) bool {
	parts := strings.SplitN(filename, "/", 2)
	if len(parts) < 2 {
		return false
	}
	return strings.Contains(parts[0], ".")
}

func printHTMLScripts() {
	fmt.Println(`<script>
var sortDirs={};
function sortTable(n){
  var t=document.getElementById("scanTable"),tbody=t.tBodies[0],rows=Array.from(tbody.rows);
  var dir=sortDirs[n]==='asc'?'desc':'asc';
  sortDirs[n]=dir;
  rows.sort(function(a,b){
    var x=a.cells[n].textContent.toLowerCase(),y=b.cells[n].textContent.toLowerCase();
    if(x<y)return dir==='asc'?-1:1;
    if(x>y)return dir==='asc'?1:-1;
    return 0;
  });
  rows.forEach(function(r){tbody.appendChild(r)});
}
function filterTable(){
  var af=document.getElementById("actionFilter").value;
  var pf=document.getElementById("prioFilter").value;
  var vfEl=document.getElementById("verFilter");
  var vf=vfEl?vfEl.value:"";
  var rows=document.getElementById("scanTable").getElementsByTagName("tr");
  for(var i=1;i<rows.length;i++){
    var r=rows[i];
    if(!r.cells||r.cells.length<13)continue;
    var actionText=r.cells[8].textContent;
    var prioText=r.cells[9].textContent;
    var verText=r.getAttribute("data-version")||"";
    var show=true;
    if(af&&actionText.indexOf(af)===-1)show=false;
    if(pf&&prioText.indexOf(pf)===-1)show=false;
    if(vf&&verText!==vf)show=false;
    r.style.display=show?"":"none";
  }
}
function selectVersionTab(el,ver){
  document.querySelectorAll(".version-tab").forEach(function(t){t.classList.remove("active")});
  el.classList.add("active");
  var vfEl=document.getElementById("verFilter");
  if(vfEl)vfEl.value=ver;
  filterTable();
}
function openMermaidModal(btn){
  var container=btn.closest(".mermaid-actions");
  if(!container)return;
  var src=container.querySelector(".mermaid");
  if(!src)return;
  var modal=document.getElementById("mermaidModal");
  var body=document.getElementById("mermaidModalBody");
  var fresh=document.createElement("div");
  fresh.className="mermaid";
  fresh.textContent=src.getAttribute("data-original")||src.textContent;
  body.innerHTML='<div class="close" onclick="closeMermaidModal(event)">&times;</div>';
  body.appendChild(fresh);
  modal.classList.add("active");
  mermaid.run({nodes:[fresh]});
}
function closeMermaidModal(e){
  var modal=document.getElementById("mermaidModal");
  if(e.target===modal||e.target.classList.contains("close")){
    modal.classList.remove("active");
    document.getElementById("mermaidModalBody").innerHTML="";
  }
}
</script>`)

	fmt.Println(`<script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js" integrity="sha384-yQ4mmBBT+vhTAwjFH0toJXNYJ6O4usWnt6EPIdWwrRvx2V/n5lXuDZQwQFeSFydF" crossorigin="anonymous"></script>`)
	fmt.Println(`<script>
mermaid.initialize({startOnLoad:false,theme:'neutral',securityLevel:'loose'});
document.querySelectorAll('details').forEach(function(d){
  d.addEventListener('toggle',function(){
    if(d.open){d.querySelectorAll('.mermaid').forEach(function(el){
      if(!el.getAttribute('data-processed')){mermaid.run({nodes:[el]})}
    })}
  })
});
</script>`)
}

func cosD(deg float64) float64 {
	return math.Cos(deg * math.Pi / 180)
}

func sinD(deg float64) float64 {
	return math.Sin(deg * math.Pi / 180)
}

func compareVersionStrings(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var na, nb int
		if i < len(pa) {
			fmt.Sscanf(pa[i], "%d", &na)
		}
		if i < len(pb) {
			fmt.Sscanf(pb[i], "%d", &nb)
		}
		if na != nb {
			return na - nb
		}
	}
	return 0
}

func htmlAction(row combinedRow, latestVersion string, cveVersions map[string][]string) string {
	action := buildAction(row, latestVersion, cveVersions)
	color := htmlActionColor(action)
	return fmt.Sprintf(`<span class="tag" style="background:%s">%s</span>`, color, action)
}

func htmlSLAColor(status string) string {
	switch status {
	case "Overdue":
		return "#d32f2f"
	case "Approaching":
		return "#f57c00"
	case "On Track":
		return "#388e3c"
	default:
		return "#9e9e9e"
	}
}

func htmlActionColor(action string) string {
	switch {
	case strings.Contains(action, "Fix on"), strings.Contains(action, "Fix latest"):
		return "#d32f2f"
	case strings.Contains(action, "Blocked"):
		return "#f57c00"
	case strings.Contains(action, "No action"):
		return "#388e3c"
	case strings.Contains(action, "Manual review"):
		return "#fbc02d"
	case strings.Contains(action, "EOL"), strings.Contains(action, "Misassigned"):
		return "#9e9e9e"
	default:
		return "#000"
	}
}
