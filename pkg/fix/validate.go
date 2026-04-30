package fix

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/razo7/vigil/pkg/goversion"
)

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

	vulnResult, err := goversion.RunGovulncheck(repoPath)
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
