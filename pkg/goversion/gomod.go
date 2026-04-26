package goversion

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	toolchainRe = regexp.MustCompile(`^toolchain\s+go(.+)$`)
	goVersionRe = regexp.MustCompile(`^go\s+(.+)$`)
)

type GoModInfo struct {
	MinVersion       string
	ToolchainVersion string
	GoLine           int
	ToolchainLine    int
}

func ReadGoMod(repoPath string) (*GoModInfo, error) {
	f, err := os.Open(filepath.Join(repoPath, "go.mod"))
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}
	defer f.Close()

	info := &GoModInfo{}
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if m := goVersionRe.FindStringSubmatch(line); len(m) > 1 {
			info.MinVersion = strings.TrimSpace(m[1])
			info.GoLine = lineNum
		}
		if m := toolchainRe.FindStringSubmatch(line); len(m) > 1 {
			info.ToolchainVersion = strings.TrimSpace(m[1])
			info.ToolchainLine = lineNum
		}
	}

	return info, nil
}

func (g *GoModInfo) EffectiveVersion() string {
	if g.ToolchainVersion != "" {
		return g.ToolchainVersion
	}
	return g.MinVersion
}

func (g *GoModInfo) EffectiveVersionLine() int {
	if g.ToolchainVersion != "" {
		return g.ToolchainLine
	}
	return g.GoLine
}

func IsPackageInGoMod(repoPath, pkg string) bool {
	data, err := os.ReadFile(filepath.Join(repoPath, "go.mod"))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), pkg)
}

func IsStdlibPackage(pkg string) bool {
	return !strings.Contains(pkg, ".")
}

func IsPackageImported(repoPath, pkg string) bool {
	if IsStdlibPackage(pkg) {
		return isStdlibImported(repoPath, pkg)
	}
	return IsPackageInGoMod(repoPath, moduleFromPackage(pkg))
}

func isStdlibImported(repoPath, pkg string) bool {
	cmd := exec.Command("grep", "-r", "--include=*.go", "-l",
		fmt.Sprintf(`"%s"`, pkg), repoPath)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return len(out) > 0
}

func moduleFromPackage(pkg string) string {
	parts := strings.Split(pkg, "/")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], "/")
	}
	return pkg
}
