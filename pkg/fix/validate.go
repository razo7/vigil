package fix

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/razo7/vigil/pkg/goversion"
)

func SecurityReview(repoPath string) ([]string, error) {
	cmd := exec.Command("git", "diff", "HEAD")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running git diff: %w", err)
	}

	diff := string(output)
	if diff == "" {
		return nil, nil
	}

	var warnings []string

	for _, line := range strings.Split(diff, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}

		if strings.HasPrefix(trimmed, "+replace ") || strings.HasPrefix(trimmed, "+\treplace ") {
			warnings = append(warnings, fmt.Sprintf("replace directive added: %s", strings.TrimPrefix(trimmed, "+")))
		}
	}

	warnings = append(warnings, checkVersionDowngrades(diff)...)
	warnings = append(warnings, checkNewDependencies(diff)...)
	warnings = append(warnings, checkRemovedSecurityImports(diff)...)

	return warnings, nil
}

func checkVersionDowngrades(diff string) []string {
	var warnings []string
	lines := strings.Split(diff, "\n")
	removedDeps := make(map[string]string)
	addedDeps := make(map[string]string)

	for _, line := range lines {
		if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			parts := parseRequireLine(strings.TrimPrefix(line, "-"))
			if parts[0] != "" {
				removedDeps[parts[0]] = parts[1]
			}
		}
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			parts := parseRequireLine(strings.TrimPrefix(line, "+"))
			if parts[0] != "" {
				addedDeps[parts[0]] = parts[1]
			}
		}
	}

	for mod, oldVer := range removedDeps {
		if newVer, ok := addedDeps[mod]; ok {
			if isDowngrade(oldVer, newVer) {
				warnings = append(warnings, fmt.Sprintf("potential version downgrade: %s %s -> %s", mod, oldVer, newVer))
			}
		}
	}
	return warnings
}

func parseRequireLine(line string) [2]string {
	line = strings.TrimSpace(line)
	fields := strings.Fields(line)
	if len(fields) >= 2 && strings.HasPrefix(fields[1], "v") {
		return [2]string{fields[0], fields[1]}
	}
	return [2]string{}
}

func isDowngrade(oldVer, newVer string) bool {
	oldParts := strings.Split(strings.TrimPrefix(oldVer, "v"), ".")
	newParts := strings.Split(strings.TrimPrefix(newVer, "v"), ".")

	maxLen := len(oldParts)
	if len(newParts) > maxLen {
		maxLen = len(newParts)
	}

	for i := 0; i < maxLen; i++ {
		old := "0"
		if i < len(oldParts) {
			old = oldParts[i]
		}
		new := "0"
		if i < len(newParts) {
			new = newParts[i]
		}
		if numericLess(new, old) {
			return true
		}
		if numericLess(old, new) {
			return false
		}
	}
	return false
}

func numericLess(a, b string) bool {
	a = stripPrerelease(a)
	b = stripPrerelease(b)
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

func stripPrerelease(s string) string {
	if i := strings.IndexByte(s, '-'); i >= 0 {
		return s[:i]
	}
	return s
}

func checkNewDependencies(diff string) []string {
	var warnings []string
	lines := strings.Split(diff, "\n")
	removedMods := make(map[string]bool)

	for _, line := range lines {
		if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			parts := parseRequireLine(strings.TrimPrefix(line, "-"))
			if parts[0] != "" {
				removedMods[parts[0]] = true
			}
		}
	}

	for _, line := range lines {
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}
		parts := parseRequireLine(strings.TrimPrefix(line, "+"))
		if parts[0] != "" && !removedMods[parts[0]] {
			warnings = append(warnings, fmt.Sprintf("new dependency added: %s %s", parts[0], parts[1]))
		}
	}
	return warnings
}

func checkRemovedSecurityImports(diff string) []string {
	var warnings []string
	securityPrefixes := []string{"crypto/", "crypto.", "security/", "security."}

	for _, line := range strings.Split(diff, "\n") {
		if !strings.HasPrefix(line, "-") || strings.HasPrefix(line, "---") {
			continue
		}
		trimmed := strings.TrimSpace(strings.TrimPrefix(line, "-"))
		trimmed = strings.Trim(trimmed, "\"")
		for _, prefix := range securityPrefixes {
			if strings.Contains(trimmed, prefix) {
				warnings = append(warnings, fmt.Sprintf("security-related import removed: %s", strings.TrimPrefix(line, "-")))
				break
			}
		}
	}
	return warnings
}

func Validate(repoPath, cveID string, runTests bool) (*ValidationResult, error) {
	vr := &ValidationResult{}

	tidy := runStep(repoPath, "go mod tidy", "go", "mod", "tidy")
	vr.Steps = append(vr.Steps, tidy)
	if !tidy.Passed {
		return vr, nil
	}

	vendor := runStep(repoPath, "go mod vendor", "go", "mod", "vendor")
	vr.Steps = append(vr.Steps, vendor)
	if !vendor.Passed {
		return vr, nil
	}

	verify := runStep(repoPath, "go mod verify", "go", "mod", "verify")
	vr.Steps = append(vr.Steps, verify)
	if !verify.Passed {
		return vr, nil
	}

	goVer := ""
	if goMod, modErr := goversion.ReadGoMod(repoPath); modErr == nil {
		goVer = goMod.EffectiveVersion()
	}
	vulnResult, err := goversion.RunGovulncheckWithVersion(repoPath, goVer)
	vulnStep := StepResult{Name: "govulncheck"}
	if err != nil {
		vulnStep.Output = err.Error()
		vulnStep.Passed = false
	} else {
		vulnStep.Passed = true
		vr.CVERemoved = !cveStillPresent(vulnResult, cveID)
		if !vr.CVERemoved {
			vulnStep.Output = fmt.Sprintf("CVE %s still present after fix", cveID)
		}
	}
	vr.Steps = append(vr.Steps, vulnStep)

	if !vr.CVERemoved {
		return vr, nil
	}

	build := runStep(repoPath, "go build", "go", "build", "./...")
	vr.Steps = append(vr.Steps, build)
	if !build.Passed {
		return vr, nil
	}

	if runTests {
		test := runStep(repoPath, "go test", "go", "test", "./...", "-count=1")
		vr.Steps = append(vr.Steps, test)
	}

	vr.Passed = vr.CVERemoved && allStepsPassed(vr.Steps)
	return vr, nil
}

func runStep(repoPath, name string, command string, args ...string) StepResult {
	cmd := exec.Command(command, args...)
	cmd.Dir = repoPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		return StepResult{
			Name:   name,
			Passed: false,
			Output: truncate(string(output), 500),
		}
	}
	return StepResult{Name: name, Passed: true}
}

func cveStillPresent(result *goversion.VulncheckResult, cveID string) bool {
	if result == nil {
		return false
	}
	for _, vuln := range result.Vulns {
		if strings.Contains(vuln.ID, cveID) {
			return true
		}
		for _, alias := range vuln.Aliases {
			if alias == cveID {
				return true
			}
		}
	}
	return false
}

func allStepsPassed(steps []StepResult) bool {
	for _, s := range steps {
		if !s.Passed {
			return false
		}
	}
	return true
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
