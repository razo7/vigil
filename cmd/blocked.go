package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/razo7/vigil/pkg/types"
	"github.com/razo7/vigil/pkg/watch"
)

const defaultRegistryDir = ".vigil"

func recordBlockedCVE(result *types.Result) {
	reg, err := watch.LoadRegistry(defaultRegistryDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: cannot load blocked registry: %v\n", err)
		return
	}

	cveID := result.Vulnerability.CVEID
	if i := strings.Index(cveID, " "); i > 0 {
		cveID = cveID[:i]
	}

	component := ""
	if ba := result.Analysis.ReleaseBranch; ba != nil {
		component = ba.CatalogComponent
	}

	entry := watch.BlockedCVE{
		TicketID:   extractTicketID(result.Source.TicketID),
		CVEID:      cveID,
		RequiredGo: result.Vulnerability.FixVersion,
		Component:  component,
		Package:    result.Vulnerability.Package,
	}

	if reg.Add(entry) {
		if err := reg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: cannot save blocked registry: %v\n", err)
			return
		}
		fmt.Fprintf(os.Stderr, "Recorded blocked CVE %s (%s) — needs Go %s\n", cveID, entry.TicketID, entry.RequiredGo)
	}
}

func recordBlockedFromScan(results []*types.Result) {
	reg, err := watch.LoadRegistry(defaultRegistryDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: cannot load blocked registry: %v\n", err)
		return
	}

	added := 0
	for _, r := range results {
		if r.Recommendation.Classification != types.BlockedByGo {
			continue
		}

		cveID := r.Vulnerability.CVEID
		if i := strings.Index(cveID, " "); i > 0 {
			cveID = cveID[:i]
		}

		component := ""
		if ba := r.Analysis.ReleaseBranch; ba != nil {
			component = ba.CatalogComponent
		}

		entry := watch.BlockedCVE{
			TicketID:   extractTicketID(r.Source.TicketID),
			CVEID:      cveID,
			RequiredGo: r.Vulnerability.FixVersion,
			Component:  component,
			Package:    r.Vulnerability.Package,
		}

		if reg.Add(entry) {
			added++
		}
	}

	if added > 0 {
		if err := reg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: cannot save blocked registry: %v\n", err)
			return
		}
		fmt.Fprintf(os.Stderr, "Recorded %d blocked CVEs to watch registry\n", added)
	}
}
