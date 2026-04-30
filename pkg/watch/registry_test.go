package watch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRegistryAddRemove(t *testing.T) {
	r := &Registry{path: "/dev/null"}

	added := r.Add(BlockedCVE{
		TicketID:   "RHWA-100",
		CVEID:      "CVE-2026-1111",
		RequiredGo: "1.25.9",
		Component:  "FAR",
	})
	if !added {
		t.Error("expected first Add to return true")
	}
	if r.Len() != 1 {
		t.Errorf("expected 1 entry, got %d", r.Len())
	}

	dup := r.Add(BlockedCVE{TicketID: "RHWA-100", CVEID: "CVE-2026-1111"})
	if dup {
		t.Error("expected duplicate Add to return false")
	}
	if r.Len() != 1 {
		t.Errorf("expected 1 entry after dup, got %d", r.Len())
	}

	r.Add(BlockedCVE{TicketID: "RHWA-200", CVEID: "CVE-2026-2222", Component: "NHC"})
	if r.Len() != 2 {
		t.Errorf("expected 2 entries, got %d", r.Len())
	}

	removed := r.Remove("RHWA-100", "CVE-2026-1111")
	if !removed {
		t.Error("expected Remove to return true")
	}
	if r.Len() != 1 {
		t.Errorf("expected 1 entry after remove, got %d", r.Len())
	}

	notRemoved := r.Remove("RHWA-999", "CVE-0000-0000")
	if notRemoved {
		t.Error("expected Remove of missing entry to return false")
	}
}

func TestRegistryFindByComponent(t *testing.T) {
	r := &Registry{path: "/dev/null"}
	r.Add(BlockedCVE{TicketID: "RHWA-1", CVEID: "CVE-1", Component: "FAR"})
	r.Add(BlockedCVE{TicketID: "RHWA-2", CVEID: "CVE-2", Component: "NHC"})
	r.Add(BlockedCVE{TicketID: "RHWA-3", CVEID: "CVE-3", Component: "FAR"})

	far := r.FindByComponent("FAR")
	if len(far) != 2 {
		t.Errorf("expected 2 FAR entries, got %d", len(far))
	}

	nhc := r.FindByComponent("NHC")
	if len(nhc) != 1 {
		t.Errorf("expected 1 NHC entry, got %d", len(nhc))
	}

	snr := r.FindByComponent("SNR")
	if len(snr) != 0 {
		t.Errorf("expected 0 SNR entries, got %d", len(snr))
	}
}

func TestRegistryLoadSave(t *testing.T) {
	dir := t.TempDir()

	r := &Registry{path: filepath.Join(dir, "blocked.json")}
	r.Add(BlockedCVE{
		TicketID:   "RHWA-100",
		CVEID:      "CVE-2026-1111",
		RequiredGo: "1.25.9",
		Component:  "FAR",
		AddedAt:    time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC),
	})

	if err := r.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := LoadRegistry(dir)
	if err != nil {
		t.Fatalf("LoadRegistry failed: %v", err)
	}
	if loaded.Len() != 1 {
		t.Fatalf("expected 1 entry, got %d", loaded.Len())
	}
	if loaded.Entries[0].TicketID != "RHWA-100" {
		t.Errorf("TicketID = %q, want RHWA-100", loaded.Entries[0].TicketID)
	}
	if loaded.Entries[0].RequiredGo != "1.25.9" {
		t.Errorf("RequiredGo = %q, want 1.25.9", loaded.Entries[0].RequiredGo)
	}
}

func TestRegistryLoadEmpty(t *testing.T) {
	dir := t.TempDir()
	r, err := LoadRegistry(dir)
	if err != nil {
		t.Fatalf("LoadRegistry failed: %v", err)
	}
	if r.Len() != 0 {
		t.Errorf("expected 0 entries for new registry, got %d", r.Len())
	}
}

func TestRegistryAddSetsTimestamp(t *testing.T) {
	r := &Registry{path: "/dev/null"}
	before := time.Now().UTC()
	r.Add(BlockedCVE{TicketID: "RHWA-1", CVEID: "CVE-1"})
	after := time.Now().UTC()

	ts := r.Entries[0].AddedAt
	if ts.Before(before) || ts.After(after) {
		t.Errorf("AddedAt = %v, expected between %v and %v", ts, before, after)
	}
}

func TestRegistrySubdir(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "nested", ".vigil")

	r := &Registry{path: filepath.Join(subdir, "blocked.json")}
	r.Add(BlockedCVE{TicketID: "RHWA-1", CVEID: "CVE-1"})

	if err := r.Save(); err != nil {
		t.Fatalf("Save with nested dir failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(subdir, "blocked.json")); err != nil {
		t.Errorf("blocked.json not created: %v", err)
	}
}
