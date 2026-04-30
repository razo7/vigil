package fix

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackupRestore(t *testing.T) {
	dir := t.TempDir()

	modContent := []byte("module example.com/test\n\ngo 1.25.3\n")
	sumContent := []byte("example.com/dep v1.0.0 h1:abc\n")

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), modContent, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), sumContent, 0644); err != nil {
		t.Fatal(err)
	}

	backup, err := BackupGoFiles(dir)
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("modified"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte("modified"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := backup.Restore(); err != nil {
		t.Fatalf("restore failed: %v", err)
	}

	restored, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(modContent) {
		t.Errorf("go.mod not restored: got %q", string(restored))
	}

	restoredSum, err := os.ReadFile(filepath.Join(dir, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	if string(restoredSum) != string(sumContent) {
		t.Errorf("go.sum not restored: got %q", string(restoredSum))
	}
}

func TestBackupRestore_NoGoSum(t *testing.T) {
	dir := t.TempDir()

	modContent := []byte("module example.com/test\n\ngo 1.25.3\n")
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), modContent, 0644); err != nil {
		t.Fatal(err)
	}

	backup, err := BackupGoFiles(dir)
	if err != nil {
		t.Fatalf("backup should succeed without go.sum: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("modified"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := backup.Restore(); err != nil {
		t.Fatalf("restore failed: %v", err)
	}

	restored, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(modContent) {
		t.Errorf("go.mod not restored: got %q", string(restored))
	}

	if _, err := os.Stat(filepath.Join(dir, "go.sum")); err == nil {
		t.Error("go.sum should not have been created")
	}
}

func TestBackup_MissingGoMod(t *testing.T) {
	dir := t.TempDir()

	_, err := BackupGoFiles(dir)
	if err == nil {
		t.Error("expected error when go.mod is missing")
	}
}
