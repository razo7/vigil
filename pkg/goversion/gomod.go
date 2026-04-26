package goversion

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	toolchainRe = regexp.MustCompile(`(?m)^toolchain\s+go(.+)$`)
	goVersionRe = regexp.MustCompile(`(?m)^go\s+(.+)$`)
)

type GoModInfo struct {
	MinVersion       string
	ToolchainVersion string
}

func ReadGoMod(repoPath string) (*GoModInfo, error) {
	data, err := os.ReadFile(filepath.Join(repoPath, "go.mod"))
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	content := string(data)
	info := &GoModInfo{}

	if m := goVersionRe.FindStringSubmatch(content); len(m) > 1 {
		info.MinVersion = strings.TrimSpace(m[1])
	}

	if m := toolchainRe.FindStringSubmatch(content); len(m) > 1 {
		info.ToolchainVersion = strings.TrimSpace(m[1])
	}

	return info, nil
}

// EffectiveVersion returns the toolchain version if set, otherwise the min version.
func (g *GoModInfo) EffectiveVersion() string {
	if g.ToolchainVersion != "" {
		return g.ToolchainVersion
	}
	return g.MinVersion
}
