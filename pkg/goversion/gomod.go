package goversion

import (
	"bufio"
	"fmt"
	"os"
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
