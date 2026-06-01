package fix

import (
	"fmt"
	"os"
	"strings"

	"github.com/razo7/vigil/pkg/goversion"
)

func CheckVariants(repoPath, fixedPackage, fixedCVE string) ([]VariantVuln, error) {
	goVer := ""
	if goMod, err := goversion.ReadGoMod(repoPath); err == nil {
		goVer = goMod.EffectiveVersion()
	}

	result, err := goversion.RunGovulncheckWithVersion(repoPath, goVer)
	if err != nil {
		return nil, fmt.Errorf("variant govulncheck: %w", err)
	}

	if result == nil {
		return nil, nil
	}

	fixedModule := moduleFromPackage(fixedPackage)

	var variants []VariantVuln
	for i := range result.Vulns {
		vuln := &result.Vulns[i]
		if isFixedCVE(vuln, fixedCVE) {
			continue
		}
		if !matchesModule(vuln, fixedModule) {
			continue
		}
		cveID := primaryCVEID(vuln)
		variants = append(variants, VariantVuln{
			CVEID:        cveID,
			Package:      vuln.Package,
			Reachability: goversion.ReachabilityLabel(vuln),
		})
	}
	return variants, nil
}

func PrintVariantWarnings(fixedPackage string, variants []VariantVuln) {
	if len(variants) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "WARNING: Variant analysis: %d related CVE(s) remain in %s after fix:\n",
		len(variants), fixedPackage)
	for _, v := range variants {
		fmt.Fprintf(os.Stderr, "  - %s (%s) -- %s\n", v.CVEID, v.Package, v.Reachability)
	}
}

func isFixedCVE(vuln *goversion.VulnEntry, fixedCVE string) bool {
	if vuln.ID == fixedCVE {
		return true
	}
	for _, alias := range vuln.Aliases {
		if alias == fixedCVE {
			return true
		}
	}
	return strings.Contains(vuln.ID, fixedCVE)
}

func matchesModule(vuln *goversion.VulnEntry, module string) bool {
	if vuln.Module == module {
		return true
	}
	if vuln.Package != "" && strings.HasPrefix(vuln.Package, module) {
		return true
	}
	return false
}

func moduleFromPackage(pkg string) string {
	if goversion.IsStdlibPackage(pkg) {
		return "stdlib"
	}
	return pkg
}

func primaryCVEID(vuln *goversion.VulnEntry) string {
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	return vuln.ID
}
