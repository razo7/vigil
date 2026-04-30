package watch

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type BlockedCVE struct {
	TicketID   string    `json:"ticket_id"`
	CVEID      string    `json:"cve_id"`
	RequiredGo string    `json:"required_go"`
	Component  string    `json:"component"`
	Package    string    `json:"package,omitempty"`
	AddedAt    time.Time `json:"added_at"`
}

type Registry struct {
	Entries   []BlockedCVE `json:"entries"`
	UpdatedAt time.Time    `json:"updated_at"`
	path      string
}

func LoadRegistry(dir string) (*Registry, error) {
	path := filepath.Join(dir, "blocked.json")
	r := &Registry{path: path}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("reading registry: %w", err)
	}

	if err := json.Unmarshal(data, r); err != nil {
		return nil, fmt.Errorf("parsing registry: %w", err)
	}
	r.path = path
	return r, nil
}

func (r *Registry) Save() error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0755); err != nil {
		return fmt.Errorf("creating registry dir: %w", err)
	}

	r.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling registry: %w", err)
	}

	return os.WriteFile(r.path, data, 0644)
}

func (r *Registry) Add(entry BlockedCVE) bool {
	for _, e := range r.Entries {
		if e.TicketID == entry.TicketID && e.CVEID == entry.CVEID {
			return false
		}
	}
	if entry.AddedAt.IsZero() {
		entry.AddedAt = time.Now().UTC()
	}
	r.Entries = append(r.Entries, entry)
	return true
}

func (r *Registry) Remove(ticketID, cveID string) bool {
	for i, e := range r.Entries {
		if e.TicketID == ticketID && e.CVEID == cveID {
			r.Entries = append(r.Entries[:i], r.Entries[i+1:]...)
			return true
		}
	}
	return false
}

func (r *Registry) FindByComponent(component string) []BlockedCVE {
	var result []BlockedCVE
	for _, e := range r.Entries {
		if e.Component == component {
			result = append(result, e)
		}
	}
	return result
}

func (r *Registry) Len() int {
	return len(r.Entries)
}
