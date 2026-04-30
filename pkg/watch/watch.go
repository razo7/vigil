package watch

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/razo7/vigil/pkg/goversion"
)

type Options struct {
	Component    string
	RegistryDir  string
	Interval     time.Duration
	Once         bool
	OperatorName string
	ImageName    string
	Version      string
}

type PromotedCVE struct {
	Entry             BlockedCVE
	DownstreamVersion string
}

func Run(ctx context.Context, opts Options) ([]PromotedCVE, error) {
	reg, err := LoadRegistry(opts.RegistryDir)
	if err != nil {
		return nil, fmt.Errorf("loading registry: %w", err)
	}

	blocked := reg.FindByComponent(opts.Component)
	if len(blocked) == 0 {
		fmt.Fprintf(os.Stderr, "No blocked CVEs for %s\n", opts.Component)
		return nil, nil
	}

	fmt.Fprintf(os.Stderr, "Checking %d blocked CVEs for %s...\n", len(blocked), opts.Component)

	var promoted []PromotedCVE
	for _, entry := range blocked {
		result, err := goversion.CheckGoVersion(opts.OperatorName, entry.RequiredGo, opts.ImageName, opts.Version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: check failed for %s/%s: %v\n", entry.TicketID, entry.CVEID, err)
			continue
		}

		if result.Available {
			fmt.Fprintf(os.Stderr, "PROMOTED: %s (%s) — Go %s now available (downstream: %s)\n",
				entry.TicketID, entry.CVEID, entry.RequiredGo, result.DownstreamVersion)
			promoted = append(promoted, PromotedCVE{
				Entry:             entry,
				DownstreamVersion: result.DownstreamVersion,
			})
			reg.Remove(entry.TicketID, entry.CVEID)
		} else {
			fmt.Fprintf(os.Stderr, "BLOCKED: %s (%s) — needs Go %s, downstream has %s\n",
				entry.TicketID, entry.CVEID, entry.RequiredGo, result.DownstreamVersion)
		}
	}

	if len(promoted) > 0 {
		if err := reg.Save(); err != nil {
			return promoted, fmt.Errorf("saving registry: %w", err)
		}
	}

	return promoted, nil
}
