package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/term"
)

var (
	jsonKeyRe       = regexp.MustCompile(`^(\s*)"([^"]+)":`)
	jsonStringRe    = regexp.MustCompile(`:\s*"(.*)"(,?)$`)
	jsonNumberRe    = regexp.MustCompile(`:\s*(\d+\.?\d*)(,?)$`)
	jsonBoolRe      = regexp.MustCompile(`:\s*(true|false)(,?)$`)
	jsonNullRe      = regexp.MustCompile(`:\s*(null)(,?)$`)
	jsonBareStringRe = regexp.MustCompile(`^(\s*)"(.*)"(,?)$`)
	ocpTierRe       = regexp.MustCompile(`(Platform Aligned|Rolling Stream)( OCP )([\d., ]+)`)
)

const (
	colorReset    = "\033[0m"
	colorKey      = "\033[36m"    // cyan
	colorString   = "\033[33m"    // yellow
	colorNumber   = "\033[35m"    // magenta
	colorBool     = "\033[34m"    // blue
	colorNull     = "\033[90m"    // gray
	colorBrace    = "\033[37m"    // white
	colorCrit     = "\033[91m"    // bright red
	colorHigh     = "\033[31m"    // red
	colorMed      = "\033[33m"    // yellow
	colorLow      = "\033[32m"    // green
	colorMagBold  = "\033[1;35m"  // bold magenta (tier)
	colorCyanBold = "\033[1;36m"  // bold cyan (OCP version)
)

func printJSON(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	if !forceColor && !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Println(string(data))
		return nil
	}

	fmt.Println(colorizeJSON(string(data)))
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

		colored := indent + colorKey + `"` + key + `"` + colorReset + ":"

		if sm := jsonStringRe.FindStringSubmatch(line); sm != nil {
			val := sm[1]
			comma := sm[2]
			if key == "call_path" {
				colored += " " + `"` + colorizeCallPath(val) + `"` + colorReset + comma
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
	case "action":
		return "\033[1;97;44m" // bold bright white on blue background
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
