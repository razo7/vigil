package goversion

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	Module         string
	Package        string
	Reachable      bool
	ModuleOnly     bool
	AffectedRanges []AffectedRange
	FixVersion       string
	InstalledVersion string
	CallPaths        []string
	TestOnly         bool
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
	Version  string             `json:"version,omitempty"`
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
	goVersion := ""
	if goMod, err := ReadGoMod(repoPath); err == nil {
		goVersion = goMod.EffectiveVersion()
	}
	return RunGovulncheckWithVersion(repoPath, goVersion)
}

func normalizeToolchainVersion(v string) string {
	if v == "" {
		return v
	}
	parts := strings.Split(v, ".")
	if len(parts) == 2 {
		return v + ".0"
	}
	return v
}

func toolchainEnv(goVersion string) string {
	if goVersion == "" {
		return "GOTOOLCHAIN=local"
	}
	v := strings.TrimPrefix(goVersion, "go")
	if isPreToolchainGo(v) {
		if err := ensureGoToolchain(v); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not install Go %s toolchain: %v — using local\n", v, err)
			return "GOTOOLCHAIN=local"
		}
	}
	return "GOTOOLCHAIN=go" + normalizeToolchainVersion(goVersion)
}

func isPreToolchainGo(version string) bool {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return false
	}
	major := 0
	minor := 0
	fmt.Sscanf(parts[0], "%d", &major)
	fmt.Sscanf(parts[1], "%d", &minor)
	return major <= 1 && minor < 21
}

func ensureGoToolchain(version string) error {
	normalized := normalizeToolchainVersion(version)
	gobin := fmt.Sprintf("go%s", normalized)

	if _, err := exec.LookPath(gobin); err == nil {
		return nil
	}

	cacheDir := filepath.Join(os.TempDir(), "vigil-toolchains")
	cachedBin := filepath.Join(cacheDir, gobin)
	if _, err := os.Stat(cachedBin); err == nil {
		os.Setenv("PATH", cacheDir+":"+os.Getenv("PATH"))
		return nil
	}

	fmt.Fprintf(os.Stderr, "Downloading Go %s toolchain for accurate govulncheck analysis...\n", version)

	goos := "linux"
	goarch := "amd64"
	tarball := fmt.Sprintf("go%s.%s-%s.tar.gz", normalized, goos, goarch)
	url := fmt.Sprintf("https://go.dev/dl/%s", tarball)

	tmpFile := filepath.Join(os.TempDir(), tarball)
	if err := downloadFile(url, tmpFile); err != nil {
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	defer os.Remove(tmpFile)

	extractDir := filepath.Join(cacheDir, "go-"+normalized)
	os.MkdirAll(extractDir, 0755)
	tarCmd := exec.Command("tar", "xzf", tmpFile, "-C", extractDir, "--strip-components=1")
	if out, err := tarCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("extracting: %s: %w", strings.TrimSpace(string(out)), err)
	}

	os.MkdirAll(cacheDir, 0755)
	goBin := filepath.Join(extractDir, "bin", "go")
	os.Symlink(goBin, cachedBin)

	os.Setenv("PATH", cacheDir+":"+os.Getenv("PATH"))
	os.Setenv("GOROOT", extractDir)

	fmt.Fprintf(os.Stderr, "Go %s toolchain ready\n", version)
	return nil
}

func RunGovulncheckWithBlame(repoPath, goVersion string) (*VulncheckResult, error) {
	result, err := RunGovulncheckWithVersion(repoPath, goVersion)
	if err != nil {
		return nil, err
	}
	annotateBlame(repoPath, result)
	return result, nil
}

func RunGovulncheckWithVersion(repoPath, goVersion string) (*VulncheckResult, error) {
	cmd := exec.Command("govulncheck", "-json", "./...")
	cmd.Dir = repoPath
	cmd.Env = append(os.Environ(), toolchainEnv(goVersion))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	if stdout.Len() == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("govulncheck failed: %w: %s", runErr, stderr.String())
		}
		return &VulncheckResult{}, nil
	}

	ownModule := ""
	if goMod, modErr := ReadGoMod(repoPath); modErr == nil {
		ownModule = goMod.ModulePath
	}
	result, err := parseGovulncheckOutput(stdout.Bytes(), ownModule)
	if err != nil {
		return nil, err
	}

	if runErr != nil && len(result.Vulns) == 0 {
		return nil, fmt.Errorf("govulncheck exited with error (possible toolchain issue): %w: %s", runErr, stderr.String())
	}

	return result, nil
}

func parseGovulncheckOutput(data []byte, ownModulePath ...string) (*VulncheckResult, error) {
	ownModule := ""
	if len(ownModulePath) > 0 {
		ownModule = ownModulePath[0]
	}
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
						repoRelPath := buildRepoRelativePath(frame.Position.Filename, frame.Module, ownModule)
						loc := repoRelPath
						if frame.Position.Line > 0 {
							loc = fmt.Sprintf("%s:%d", repoRelPath, frame.Position.Line)
						}
						name += " (" + loc + ")"
						lastFilename = frame.Position.Filename
					}
					callParts = append(callParts, name)
				} else if frame.Package != "" {
					isPackageLevel = true
				}
				if entry.Module == "" && frame.Module != "" {
					entry.Module = frame.Module
				}
				if entry.InstalledVersion == "" && frame.Version != "" {
					entry.InstalledVersion = strings.TrimPrefix(frame.Version, "v")
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

var blameFrameRe = regexp.MustCompile(`\(([^)]+):(\d+)\)$`)

func annotateBlame(repoPath string, result *VulncheckResult) {
	blameCount := 0
	for i := range result.Vulns {
		for j, path := range result.Vulns[i].CallPaths {
			frames := strings.Split(path, " → ")
			changed := false
			for k, frame := range frames {
				m := blameFrameRe.FindStringSubmatch(frame)
				if m == nil {
					continue
				}
				filePath := m[1]
				line := m[2]
				if strings.HasPrefix(filePath, "src/") {
					continue
				}
				sha := gitBlame(repoPath, filePath, line)
				if sha != "" {
					frames[k] = strings.TrimSuffix(frame, ")") + "@" + sha + ")"
					changed = true
					blameCount++
				}
			}
			if changed {
				result.Vulns[i].CallPaths[j] = strings.Join(frames, " → ")
			}
		}
	}
	if blameCount > 0 {
		fmt.Fprintf(os.Stderr, "Annotated %d call path frames with git blame\n", blameCount)
	}
}

func gitBlame(repoPath, filePath, line string) string {
	fullPath := filepath.Join(repoPath, filePath)
	if _, err := os.Stat(fullPath); err != nil {
		return ""
	}
	cmd := exec.Command("git", "blame", "-L", line+","+line, "--porcelain", "--", filePath)
	cmd.Dir = repoPath
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	if len(fields) > 0 && len(fields[0]) >= 7 {
		sha := fields[0]
		if sha == strings.Repeat("0", len(sha)) {
			return ""
		}
		return sha[:7]
	}
	return ""
}

func downloadFile(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func buildRepoRelativePath(filename, module, ownModule string) string {
	if module == "stdlib" {
		if strings.HasPrefix(filename, "src/") {
			return filename
		}
		if i := strings.Index(filename, "/src/"); i >= 0 {
			return filename[i+1:]
		}
		return "src/" + filename
	}
	if module == ownModule || module == "" {
		return filename
	}
	return "vendor/" + module + "/" + filename
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
