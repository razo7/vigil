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
.filter-bar{margin:12px 0;display:flex;gap:8px;align-items:center;font-size:13px}
.filter-bar select{padding:4px 8px;border-radius:4px;border:1px solid #d1d5da}
.mermaid{margin:8px 0 16px;padding:12px;background:#f6f8fa;border-radius:6px}
.action-list{list-style:none;padding:0;margin:0}
.action-list li{padding:6px 0;border-bottom:1px solid #f0f0f0;font-size:13px}
@media print{th{position:static}tr:nth-child(even){background:#fafbfc !important}}
</style></head><body>
<h1>🔍 Vigil Scan Report</h1>
<p>Generated: %s</p>
`, time.Now().Format("2006-01-02 15:04"))

	// Donut chart + severity bar
	total := len(rows)
	fmt.Println(`<div class="cards">`)

	// Classification donut
	fmt.Println(`<div class="card"><h3>📊 Classification Breakdown</h3>`)
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
			{"Not Go", classCounts[types.NotGo], "#fbc02d"},
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

	// Severity bar
	fmt.Println(`<div class="card"><h3>⚡ Severity Distribution</h3>`)
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

	// Top action items
	fmt.Println(`<div class="card"><h3>⚡ Top Action Items</h3><ol class="action-list">`)
	actionCount := 0
	for _, row := range rows {
		if row.classification != types.FixableNow || actionCount >= 10 {
			continue
		}
		actionCount++
		ticket := row.ticket
		if row.ticketURL != "" {
			ticket = fmt.Sprintf(`<a href="%s">%s</a>`, row.ticketURL, row.ticket)
		}
		fmt.Printf("<li>%s <span class=\"tag\" style=\"background:%s\">%s</span> %s %s</li>\n",
			ticket, htmlPrioColor(row.priority), shortPriority(row.priority), row.pkg, row.reachability)
	}
	fmt.Println(`</ol></div></div>`)

	// Filter bar
	fmt.Println(`<div class="filter-bar">Filter: <select id="classFilter" onchange="filterTable()">
<option value="">All</option>
<option value="Fixable Now">Fixable Now</option>
<option value="Not Reachable">Not Reachable</option>
<option value="Blocked by Go">Blocked by Go</option>
<option value="Not Go">Not Go</option>
<option value="Misassigned">Misassigned</option>
</select></div>`)

	// Table
	fmt.Println(`<table id="scanTable"><thead><tr>
<th onclick="sortTable(0)">SRC</th><th onclick="sortTable(1)">TICKET</th><th onclick="sortTable(2)">CREATED</th><th onclick="sortTable(3)">UPDATED</th><th onclick="sortTable(4)">CVE</th><th onclick="sortTable(5)">VERSION</th><th onclick="sortTable(6)">LANG</th><th onclick="sortTable(7)">STATUS</th><th onclick="sortTable(8)">CLASSIFICATION</th><th onclick="sortTable(9)">PRIORITY</th><th onclick="sortTable(10)">PACKAGE</th><th onclick="sortTable(11)">CVSS</th><th onclick="sortTable(12)">REACHABILITY</th><th onclick="sortTable(13)">BACKPORT</th>
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

		reachCell := reachDisplay
		hasChain := (strings.HasPrefix(row.reachability, "REACHABLE") || strings.HasPrefix(row.reachability, "PACKAGE-LEVEL")) &&
			(len(row.callPaths) > 0 || row.importChain != "")
		if hasChain {
			var frames []string
			for _, cp := range row.callPaths {
				parts := strings.Split(cp, " → ")
				frames = append(frames, parts...)
			}
			if len(frames) == 0 && row.importChain != "" {
				frames = strings.Split(row.importChain, " → ")
			}
			if len(frames) > 10 {
				frames = append(frames[:3], append([]string{"..."}, frames[len(frames)-3:]...)...)
			}
			if len(frames) > 1 {
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
				}
				reachCell = fmt.Sprintf(`%s<details><summary>🔎 call path</summary><div class="mermaid">%s</div></details>`,
					reachDisplay, mermaid.String())
			}
		}

		bpCell := backportVerdict(row.cveID, row.version, latestVersion, cveVersions, row.classification)

		fmt.Printf(`<tr id="%s"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%.1f</td><td>%s</td><td>%s</td></tr>`,
			row.ticket, row.src, ticketCell, row.created, row.updated, cveCell, row.version, langDisplay, row.status, classCell, prioCell, pkgDisplay, row.cvss, reachCell, bpCell)
		fmt.Println()
	}

	fmt.Println(`</tbody></table>`)

	// JavaScript for sorting and filtering
	fmt.Println(`<script>
function sortTable(n){var t=document.getElementById("scanTable"),r=t.rows,s=true,d="asc",c=true;
while(c){c=false;for(var i=1;i<r.length-1;i++){s=false;
var x=r[i].cells[n],y=r[i+1].cells[n];
var xv=x.textContent.toLowerCase(),yv=y.textContent.toLowerCase();
if(d=="asc"?xv>yv:xv<yv){s=true;break}}
if(s){r[i].parentNode.insertBefore(r[i+1],r[i]);c=true}else if(d=="asc"){d="desc";c=true}}}
function filterTable(){var f=document.getElementById("classFilter").value;
var t=document.getElementById("scanTable").getElementsByTagName("tr");
for(var i=1;i<t.length;i++){var c=t[i].cells[8];
if(!c)continue;t[i].style.display=(!f||c.textContent.indexOf(f)>-1)?"":"none"}}
</script>`)

	fmt.Println(`<script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>`)
	fmt.Println(`<script>
mermaid.initialize({startOnLoad:false,theme:'neutral'});
document.querySelectorAll('details').forEach(function(d){
  d.addEventListener('toggle',function(){
    if(d.open){d.querySelectorAll('.mermaid').forEach(function(el){
      if(!el.getAttribute('data-processed')){mermaid.run({nodes:[el]})}
    })}
  })
});
</script>`)

	fmt.Println(`</body></html>`)
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

func backportVerdict(cveID, version, latestVersion string, cveVersions map[string][]string, classification types.Classification) string {
	if classification == types.Misassigned {
		return `<span class="tag" style="background:#9e9e9e">↩️ N/A</span>`
	}
	if classification == types.NotGo {
		return `<span class="tag" style="background:#9e9e9e">🐍 N/A</span>`
	}
	if classification == types.NotReachable {
		return `<span class="tag" style="background:#388e3c">🟢 No</span>`
	}

	if version == "" {
		return `<span class="tag" style="background:#d32f2f">🔴 Fix latest</span>`
	}

	isLatest := version == latestVersion || compareVersionStrings(version, latestVersion) >= 0

	versions := cveVersions[cveID]
	affectsLatest := false
	for _, v := range versions {
		if v == "main" || v == latestVersion || compareVersionStrings(v, latestVersion) >= 0 {
			affectsLatest = true
			break
		}
	}

	if isLatest {
		return `<span class="tag" style="background:#d32f2f">🔴 Fix latest</span>`
	}
	if affectsLatest {
		return `<span class="tag" style="background:#f57c00">🟠 Fix + backport</span>`
	}
	return `<span class="tag" style="background:#fbc02d;color:#333">🟡 Backport only</span>`
}
