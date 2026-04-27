package goversion

import (
	"bytes"
	"encoding/json"
	"io"
	"os/exec"
	"strings"
)

type VulncheckResult struct {
	Vulns []VulnEntry
}

type AffectedRange struct {
	Introduced string
	Fixed      string
}

type VulnEntry struct {
	ID             string
	Summary        string
	Aliases        []string
	Package        string
	Reachable      bool
	ModuleOnly     bool
	AffectedRanges []AffectedRange
	FixVersion     string
	CallPaths      []string
	TestOnly       bool
}

type vulncheckMessage struct {
	Finding *vulncheckFinding `json:"finding,omitempty"`
	OSV     *vulncheckOSV     `json:"osv,omitempty"`
}

type vulncheckFinding struct {
	OSV        string           `json:"osv"`
	Trace      []vulncheckFrame `json:"trace"`
	FixVersion string           `json:"fixed_version,omitempty"`
}

type vulncheckFrame struct {
	Module   string             `json:"module,omitempty"`
	Package  string             `json:"package,omitempty"`
	Function string             `json:"function,omitempty"`
	Receiver string             `json:"receiver,omitempty"`
	Position *vulncheckPosition `json:"position,omitempty"`
}

type vulncheckPosition struct {
	Filename string `json:"filename,omitempty"`
	Line     int    `json:"line,omitempty"`
}

type vulncheckOSV struct {
	ID       string              `json:"id"`
	Summary  string              `json:"summary,omitempty"`
	Aliases  []string            `json:"aliases,omitempty"`
	Affected []vulncheckAffected `json:"affected,omitempty"`
}

type vulncheckAffected struct {
	Package vulncheckPkg     `json:"package"`
	Ranges  []vulncheckRange `json:"ranges,omitempty"`
}

type vulncheckPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type vulncheckRange struct {
	Events []vulncheckEvent `json:"events,omitempty"`
}

type vulncheckEvent struct {
	Fixed      string `json:"fixed,omitempty"`
	Introduced string `json:"introduced,omitempty"`
}

func RunGovulncheck(repoPath string) (*VulncheckResult, error) {
	cmd := exec.Command("govulncheck", "-json", "./...")
	cmd.Dir = repoPath

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run() // govulncheck exits non-zero when vulns found; we parse stdout regardless

	if stdout.Len() == 0 {
		return &VulncheckResult{}, nil
	}

	return parseGovulncheckOutput(stdout.Bytes())
}

func parseGovulncheckOutput(data []byte) (*VulncheckResult, error) {
	result := &VulncheckResult{}
	osvMap := make(map[string]*vulncheckOSV)
	findingsMap := make(map[string][]*vulncheckFinding)

	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var msg vulncheckMessage
		err := dec.Decode(&msg)
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		if msg.OSV != nil {
			osvMap[msg.OSV.ID] = msg.OSV
		}

		if msg.Finding != nil {
			findingsMap[msg.Finding.OSV] = append(findingsMap[msg.Finding.OSV], msg.Finding)
		}
	}

	for id, findings := range findingsMap {
		entry := VulnEntry{
			ID: id,
		}

		if osv, ok := osvMap[id]; ok {
			entry.Aliases = osv.Aliases
			entry.Summary = osv.Summary
		}

		isReachable := false
		isPackageLevel := false
		allTestOnly := true
		seen := make(map[string]bool)
		var allPaths []string

		for _, finding := range findings {
			var callParts []string
			var lastFilename string
			for _, frame := range finding.Trace {
				if frame.Function != "" {
					isReachable = true
					name := frame.Function
					if frame.Receiver != "" {
						name = frame.Receiver + "." + name
					}
					if frame.Position != nil && frame.Position.Filename != "" {
						name += " (" + frame.Position.Filename + ")"
						lastFilename = frame.Position.Filename
					}
					callParts = append(callParts, name)
				} else if frame.Package != "" {
					isPackageLevel = true
				}
				if entry.Package == "" && frame.Package != "" {
					entry.Package = frame.Package
				}
			}
			if len(callParts) > 0 {
				if !isTestFile(lastFilename) {
					allTestOnly = false
				}
				path := strings.Join(callParts, " → ")
				if !seen[path] {
					seen[path] = true
					allPaths = append(allPaths, path)
				}
			}

			if finding.FixVersion != "" && entry.FixVersion == "" {
				entry.FixVersion = strings.TrimPrefix(finding.FixVersion, "v")
			}
		}

		entry.Reachable = isReachable
		if isReachable && allTestOnly && len(allPaths) > 0 {
			entry.TestOnly = true
		}
		entry.ModuleOnly = !isReachable && !isPackageLevel

		if osv, ok := osvMap[id]; ok {
			for _, affected := range osv.Affected {
				if entry.Package == "" {
					entry.Package = affected.Package.Name
				}
				for _, r := range affected.Ranges {
					entry.AffectedRanges = append(entry.AffectedRanges, parseRangeEvents(r.Events)...)
				}
				if entry.FixVersion == "" {
					for _, ar := range entry.AffectedRanges {
						if ar.Fixed != "" {
							entry.FixVersion = ar.Fixed
							break
						}
					}
				}
			}
		}

		entry.CallPaths = allPaths

		result.Vulns = append(result.Vulns, entry)
	}

	return result, nil
}

func parseRangeEvents(events []vulncheckEvent) []AffectedRange {
	var ranges []AffectedRange
	var current AffectedRange
	for _, ev := range events {
		if ev.Introduced != "" {
			current.Introduced = strings.TrimPrefix(ev.Introduced, "v")
		}
		if ev.Fixed != "" {
			current.Fixed = strings.TrimPrefix(ev.Fixed, "v")
			ranges = append(ranges, current)
			current = AffectedRange{}
		}
	}
	if current.Introduced != "" {
		ranges = append(ranges, current)
	}
	return ranges
}

func ReachabilityLabel(entry *VulnEntry) string {
	if entry == nil {
		return "UNKNOWN"
	}
	if entry.Reachable && entry.TestOnly {
		return "TEST-ONLY"
	}
	if entry.Reachable {
		return "REACHABLE"
	}
	if !entry.ModuleOnly {
		return "PACKAGE-LEVEL"
	}
	return "MODULE-LEVEL"
}

func isTestFile(filename string) bool {
	if filename == "" {
		return false
	}
	return strings.HasSuffix(filename, "_test.go") ||
		strings.Contains(filename, "/test/") ||
		strings.Contains(filename, "/tests/") ||
		strings.Contains(filename, "/e2e/")
}
