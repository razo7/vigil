# ACTION Column Design (v0.0.4)

Consolidates CLASSIFICATION + BACKPORT into a single actionable directive per CVE ticket.

## Decision Tree

```
1. Is it a Go CVE?
   ├─ No → ❓ Unknown (manual review)
   └─ Yes ↓

2. Is the image a bundle?
   ├─ Yes + CVE targets Go code → ↩️ Misassigned (bundle has no Go runtime)
   ├─ Yes + CVE targets non-Go → ❓ Unknown (check if bundle uses it)
   └─ No ↓

3. Is the operator version EOL?
   ├─ Yes → ↩️ EOL (no action)
   └─ No ↓

4. Is the code reachable? (govulncheck + fix-function match)
   ├─ Not imported → 🟢 No action (not imported)
   ├─ Module-level only → 🟢 No action (go.mod only)
   ├─ Fix-function mismatch → 🟢 No action (fixed functions not called)
   │   └─ Only for Go stdlib CVEs with Gerrit CLs
   │      Third-party deps: falls back to govulncheck only
   └─ Reachable or Package-level ↓

5. Is the fix deployable? (Go version check via skopeo)
   ├─ Fix needs newer Go than downstream → 🟠⏳ Blocked (needs Go X.Y.Z)
   │   └─ Downstream Go version from:
   │      1. Cached skopeo result (from last VPN run)
   │      2. --go-version flag (explicit override)
   │      3. Live skopeo query (requires VPN)
   └─ Fix is deployable ↓

6. Which supported versions are affected?
   ├─ Check ALL supported versions (not just latest)
   ├─ List each affected version
   └─ 🔴🔧 Fix on v0.2, v0.4, v0.6
```

## ACTION Column Values

| Value | Meaning | Input signals |
|-------|---------|---------------|
| 🔴🔧 Fix on v0.2, v0.4 | Specific versions needing fix | Reachability + version scan |
| 🟠⏳ Blocked (Go 1.26+) | Can't deploy fix yet | Downstream Go version check |
| 🟢 No action | Not reachable / not imported | govulncheck reachability |
| 🟢 No action (verified) | Fix functions not called | govulncheck + Gerrit CL |
| ❓ Manual review | Non-Go or ambiguous | Language detection |
| ↩️ EOL | Unsupported version | OCP lifecycle |
| ↩️ Misassigned | Go CVE on bundle image | Image type detection |

## Reachability Confidence

| Confidence | Method | When |
|------------|--------|------|
| High | govulncheck + Gerrit fix-function match | Go stdlib CVEs with Gerrit CLs |
| Medium | govulncheck only (REACHABLE/PACKAGE-LEVEL) | All Go CVEs |
| Low | No govulncheck (e.g., non-Go, bundle) | Non-Go CVEs |

## Downstream Go Version Sources (priority order)

1. **Cached skopeo result** — file `.vigil/downstream-go-cache.json` from last VPN-connected run
2. **`--go-version` flag** — explicit CLI override
3. **Live skopeo query** — requires VPN access to gitlab.cee.redhat.com
4. **Fallback** — use go.mod version with warning: "downstream Go version unknown, using go.mod"

## v0.0.4 Design Tasks

### Fix-function mismatch for third-party dependencies

Currently function-level mismatch detection only works for Go stdlib CVEs (via Gerrit CL patches). Third-party libraries (grpc, x/net, controller-runtime, etc.) fall back to govulncheck package-level reachability only.

**Goal:** Extend fix-function detection to third-party deps by:
1. Fetching the fix commit from the library's GitHub/GitLab repo (not Gerrit)
2. Parsing the diff to extract changed functions (same logic as `fetchFixFunctions()`)
3. Cross-referencing against govulncheck call paths

**Sources for fix commits:**
- GitHub: `https://api.github.com/repos/{owner}/{repo}/compare/{fix_version_base}...{fix_version}`
- Go vulnerability database: `https://vuln.go.dev/ID/{vuln-id}.json` contains fix commit references
- NVD/CVE advisories: often link to the fix PR/commit

**Challenges:**
- Not all libraries have clean single-commit fixes (some are multi-commit)
- Need to map CVE → library → fix commit → changed functions
- Rate limiting on GitHub API for high-volume scanning

### Skopeo cache for CI without VPN

Cache downstream Go version results from local VPN-connected runs to `.vigil/downstream-go-cache.json`. CI weekly scan reads cached values instead of requiring `--go-version` override. Cache entries keyed by `{operator}@{version}` with timestamp for staleness detection.

### Multi-branch CVE discovery

Currently `vigil scan --discover` only scans the default branch (main/HEAD). CVEs in older supported release branches are invisible. This should be changed to scan all supported branches (or at minimum the oldest supported one — most likely to have unfixed CVEs).

Approach:
1. Look up supported versions from lifecycle config for the component
2. For each supported version, checkout the corresponding release branch/tag
3. Run govulncheck per branch
4. Merge results, deduplicating CVEs that appear across branches
5. Report which branches each CVE affects (ties into ACTION column "Fix on v0.2, v0.4")

Tags should be preferred over branches when available (more precise — corresponds to an actual release).

### Container health index integration

The `health_index` field in component config provides per-image URLs to container security scanners (e.g., Red Hat catalog grades A-F, Quay security scan). Currently stored as reference links only.

Future integration:
1. Fetch health grade from the catalog URL (API or scrape)
2. Include grade in scan output alongside govulncheck results
3. Use grade as a prioritization signal: grade F components get higher priority than grade A
4. Show grade in HTML report dashboard cards

Config format (already in `rhwa_jira_example.yaml`):
```yaml
health_index:
  operator: "https://catalog.redhat.com/en/software/containers/..."
  bundle: "https://catalog.redhat.com/en/software/containers/..."
```

### Persistent report hosting

Currently reports are GitHub Actions artifacts (downloaded as zip, expire in 90 days). Need a browsable URL that team members can bookmark.

Options considered:
- **GitHub Pages (public)**: simplest but CVE data (ticket IDs, reachability, severity) would be public. Not suitable for security-sensitive data.
- **Private GitHub repo + Pages**: separate repo with restricted access, workflow pushes reports there. Team-only visibility. Recommended for internal use.
- **GitLab Pages (gitlab.cee.redhat.com)**: behind VPN, most secure. Requires GitLab CI pipeline to receive reports.
- **S3/GCS with IAM**: scalable but extra infra.

**Recommended**: Private GitHub repo with Pages. The weekly scan workflow pushes `consolidated-report.html` to a `gh-pages` branch on a private repo. Team accesses via `https://<org>.github.io/<private-repo>/`. Historical reports preserved as dated files.

### Konflux Conforma integration

Use Konflux Conforma test results as an additional input for component health and CVE state. See FAR example: https://konflux-ui.apps.stone-prod-p02.hjvn.p1.openshiftapps.com/ns/rhwa-tenant/applications/far-0-8/pipelineruns/far-0-8-enterprise-contract-5bspc/logs
