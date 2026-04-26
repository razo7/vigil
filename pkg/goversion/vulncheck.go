package goversion

import (
	"bytes"
	"encoding/json"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
)

type VulncheckResult struct {
	Vulns []VulnEntry
}

type VulnEntry struct {
	ID                string
	Aliases           []string
	Package           string
	Reachable         bool
	ModuleOnly        bool
	IntroducedVersion string
	FixVersion        string
	CallPath          string
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
	ID       string           `json:"id"`
	Aliases  []string         `json:"aliases,omitempty"`
	Affected []vulncheckAffected `json:"affected,omitempty"`
}

type vulncheckAffected struct {
	Package vulncheckPkg       `json:"package"`
	Ranges  []vulncheckRange   `json:"ranges,omitempty"`
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
	findingsMap := make(map[string]*vulncheckFinding)

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
			existing, ok := findingsMap[msg.Finding.OSV]
			if !ok || len(msg.Finding.Trace) > len(existing.Trace) {
				findingsMap[msg.Finding.OSV] = msg.Finding
			}
		}
	}

	for id, finding := range findingsMap {
		entry := VulnEntry{
			ID: id,
		}

		if osv, ok := osvMap[id]; ok {
			entry.Aliases = osv.Aliases
		}

		isReachable := false
		isPackageLevel := false
		var callParts []string

		for _, frame := range finding.Trace {
			if frame.Function != "" {
				isReachable = true
				name := frame.Function
				if frame.Receiver != "" {
					name = frame.Receiver + "." + name
				}
				if frame.Position != nil && frame.Position.Filename != "" {
					name += " (" + sourceLocation(frame.Package, frame.Position.Filename) + ")"
				}
				callParts = append(callParts, name)
			} else if frame.Package != "" {
				isPackageLevel = true
			}
			if entry.Package == "" && frame.Package != "" {
				entry.Package = frame.Package
			}
		}

		entry.Reachable = isReachable
		entry.ModuleOnly = !isReachable && !isPackageLevel

		if osv, ok := osvMap[id]; ok {
			for _, affected := range osv.Affected {
				if entry.Package == "" {
					entry.Package = affected.Package.Name
				}
				for _, r := range affected.Ranges {
					for _, ev := range r.Events {
						if ev.Introduced != "" && entry.IntroducedVersion == "" {
							entry.IntroducedVersion = strings.TrimPrefix(ev.Introduced, "v")
						}
						if ev.Fixed != "" && entry.FixVersion == "" {
							entry.FixVersion = strings.TrimPrefix(ev.Fixed, "v")
						}
					}
				}
			}
		}

		if finding.FixVersion != "" {
			entry.FixVersion = strings.TrimPrefix(finding.FixVersion, "v")
		}

		if len(callParts) > 0 {
			entry.CallPath = strings.Join(callParts, " → ")
		}

		result.Vulns = append(result.Vulns, entry)
	}

	return result, nil
}

func sourceLocation(pkg, filename string) string {
	base := filepath.Base(filename)
	if pkg == "" {
		return base
	}
	parts := strings.Split(pkg, "/")
	if len(parts) > 3 {
		pkg = strings.Join(parts[len(parts)-3:], "/")
	}
	return pkg + "/" + base
}
