package fix

import (
	"fmt"
	"os"
	"path/filepath"
)

type Backup struct {
	repoPath string
	goMod    []byte
	goSum    []byte
	hasSum   bool
}

func BackupGoFiles(repoPath string) (*Backup, error) {
	goMod, err := os.ReadFile(filepath.Join(repoPath, "go.mod"))
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	b := &Backup{
		repoPath: repoPath,
		goMod:    goMod,
	}

	goSum, err := os.ReadFile(filepath.Join(repoPath, "go.sum"))
	if err == nil {
		b.goSum = goSum
		b.hasSum = true
	}

	return b, nil
}

func (b *Backup) Restore() error {
	if err := os.WriteFile(filepath.Join(b.repoPath, "go.mod"), b.goMod, 0644); err != nil {
		return fmt.Errorf("restoring go.mod: %w", err)
	}

	if b.hasSum {
		if err := os.WriteFile(filepath.Join(b.repoPath, "go.sum"), b.goSum, 0644); err != nil {
			return fmt.Errorf("restoring go.sum: %w", err)
		}
	}

	return nil
}
