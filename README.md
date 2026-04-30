# Vigil

Deterministic CVE assessment tool for [medik8s](https://github.com/medik8s) operators.

**Vigil** (Latin: *watchfulness, alertness*) automates the triage of CVE tickets by combining `govulncheck` reachability analysis, CVSS scoring, OCP lifecycle data, and misassignment detection into a single deterministic pipeline. No LLM judgment — every classification decision is codified in Go.

## Why

Each medik8s operator accumulates CVE tickets faster than the team can manually triage them. Most turn out to be non-issues: wrong component, unreachable code paths, or unsupported old versions. Vigil replaces that manual triage with a repeatable, auditable assessment.

In the FAR pilot (23 open + 19 closed tickets), the typical breakdown is:

| Classification | Count | What it means |
|---|---|---|
| misassigned | ~13 | Wrong image/version (e.g., RHEL8 ticket for EOL operator) |
| not-go | ~5 | Python/non-Go CVE assigned to a Go operator |
| not-reachable | ~5 | Go CVE exists in dependency but no call path reaches it |
| fixable-now | 0 | Fix available and downstream supports it |
| blocked-by-go | 0 | Fix needs newer Go than downstream base image provides |

This matches historical data: 12 of 19 closed FAR tickets were resolved as "Not a Bug".

## How it works

### Single ticket assessment (`vigil assess`)

```
vigil assess RHWA-881
       │
       ├─ 1. Fetch Jira ticket → extract CVE ID, component, operator version
       ├─ 2. Auto-clone operator repo (or use local path)
       ├─ 3. Checkout correct release branch via git worktree
       ├─ 4. Read go.mod → current Go version
       ├─ 5. Run govulncheck -json ./... → reachability + call path
       ├─ 6. Fetch CVSS score from cve.org API
       ├─ 7. Map operator version → OCP version → support phase
       ├─ 8. Check misassignment (bundle images, RHEL8 thresholds)
       ├─ 9. Classify + assign priority
       ├─ 10. Re-check against main branch (if release branch was scanned)
       └─ 11. Output JSON (optionally post to Jira)
```

### Batch scan (`vigil scan`)

```
vigil scan --component FAR --short --trivy
       │
       ├─ Phase 1: Jira assessment
       │    └─ For each CVE ticket → run full assess pipeline
       │
       ├─ Phase 2: govulncheck discovery
       │    ├─ Run govulncheck once on the operator repo
       │    ├─ Cross-reference findings against Jira tickets
       │    └─ Flag untracked vulnerabilities (SRC=GVC)
       │
       ├─ Phase 3: Trivy scan (--trivy)
       │    ├─ Run trivy fs on the operator repo
       │    ├─ Deduplicate against Jira + govulncheck findings
       │    └─ Flag Trivy-only vulnerabilities (SRC=Trivy)
       │
       └─ Phase 4: Combined output
            ├─ Merge all sources (SRC: Jira/GVC/Trivy/J+G/J+T/G+T/J+G+T)
            ├─ Record blocked CVEs to watch registry
            └─ Sort by source → status → priority → reachability → CVSS
```

## Install

```bash
go install github.com/razo7/vigil@latest

# Requires govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest
```

### Container

```bash
# Pull pre-built image
podman pull quay.io/oraz/vigil:latest

# Or build locally (copies host RH CA certs for internal GitLab access)
make docker-build

# Run
podman run --rm -t \
  -e JIRA_API_TOKEN=$JIRA_API_TOKEN \
  -e JIRA_EMAIL=user@redhat.com \
  -e GITLAB_PRIVATE_TOKEN=$GITLAB_PRIVATE_TOKEN \
  quay.io/oraz/vigil:latest scan --component FAR --short --trivy
```

The container image includes govulncheck, Trivy, skopeo, and git. Red Hat IT Root CA certificates are embedded at build time for `gitlab.cee.redhat.com` access.

## Usage

### Assess a single ticket

```bash
# Auto-detect repo from ticket component
vigil assess RHWA-881

# Use local repo
vigil assess RHWA-881 --repo-path /path/to/fence-agents-remediation

# Use remote repo
vigil assess RHWA-881 --repo-path https://github.com/medik8s/fence-agents-remediation.git

# Post result as Jira comment
vigil assess RHWA-881 --jira
```

### Batch scan all tickets for a component

```bash
# Short table with all detection sources
vigil scan --component FAR --short --trivy

# Full JSON output (detailed per-ticket results)
vigil scan --component FAR --trivy

# Include closed tickets for historical reference
vigil scan --component FAR --short --include-closed

# Filter by time range (last week, 30 days, 1 year, or specific date)
vigil scan --component FAR --short --since 1w
vigil scan --component FAR --short --since 30d
vigil scan --component FAR --short --since 1y
vigil scan --component FAR --short --include-closed --since 2025-01-01

# Post results to Jira and write aggregate summary
vigil scan --component FAR --jira --summary-file vigil-summary.json
```

Supported components: `FAR`, `SNR`, `NHC`, `NMO`, `MDR`, `SBR`, `NHC-CONSOLE`.

Scan queries both RHWA and ECOPROJECT Jira projects for CVE tickets matching the component.

### Discover-only mode (govulncheck)

```bash
# Run govulncheck against the component repo without Jira assessment
vigil scan --component FAR --discover

# With a local repo path
vigil scan --component FAR --discover --repo-path /path/to/fence-agents-remediation
```

Discovery mode runs `govulncheck` independently to find vulnerabilities that may not have Jira tickets yet. Results are cross-referenced against existing Jira tickets when a component is specified.

### Check downstream Go version (`vigil check-goversion`)

```bash
# Check if FAR downstream has Go 1.25.9
vigil check-goversion --operator FAR --want 1.25.9

# Check a specific operator version
vigil check-goversion --operator FAR --want 1.25.9 --version 0.4

# Check all operators
vigil check-goversion --want 1.25.9
```

### Watch blocked CVEs (`vigil watch`)

```bash
# One-time check for FAR blocked CVEs
vigil watch --component FAR --once

# Poll every 24 hours
vigil watch --component FAR --interval 24h

# Check all components once
vigil watch --once
```

Watch monitors CVEs classified as "Blocked by Go" and re-checks whether the required Go version is now available in the downstream base image. Blocked CVEs are automatically recorded by `vigil scan` and `vigil assess`.

### Example output

```json
{
  "source": {
    "ticket_id": "RHWA-811 (https://redhat.atlassian.net/browse/RHWA-811)",
    "affected operator version": "fence-agents-remediation:v0.4",
    "reporter": "Dhananjay Arunesh",
    "assignee": "Or Raz",
    "due_date": "2026-04-20",
    "jira_priority": "Undefined",
    "affects_rhwa_versions": "rhwa-24.2",
    "rhwa-ocp_support": [
      "Platform Aligned OCP 4.16: EUS1 until 2026-06-27, EOL 2027-06-27"
    ]
  },
  "vulnerability": {
    "cve_id": "CVE-2026-27137 (https://www.cve.org/CVERecord?id=CVE-2026-27137)",
    "description": "Incorrect enforcement of email constraints in crypto/x509.",
    "severity": 7.5,
    "severity_label": "HIGH",
    "vuln_id": "GO-2026-4599",
    "package": "crypto/x509",
    "fix_version": "1.26.1 (https://go-review.googlesource.com/c/go/+/752182)",
    "fix_functions": "src/crypto/x509/constraints.go:query, src/crypto/x509/constraints.go:checkConstraints",
    "affected_go_versions": ">= 1.26.0-0, < 1.26.1 (https://pkg.go.dev/vuln/GO-2026-4599)",
    "cwe": "CWE-295",
    "references": "https://go.dev/issue/77952, https://pkg.go.dev/vuln/GO-2026-4599"
  },
  "analysis": {
    "release_branch": {
      "reachability": "MODULE-LEVEL (in go.mod but package not imported)",
      "catalog_component": "fence-agents-remediation-rhel8-operator (https://catalog.redhat.com/...)",
      "upstream": {
        "branch": "release-0.4",
        "go_version": "1.20 (https://github.com/medik8s/fence-agents-remediation/blob/release-0.4/go.mod#L3)"
      },
      "downstream": {
        "branch": "rhwa-far-0.4-rhel-8",
        "go_version": "1.20.12 (https://gitlab.cee.redhat.com/dragonfly/...)"
      }
    },
    "fix_upstream?": {
      "reachability": "MODULE-LEVEL (in go.mod but package not imported)",
      "go_version": "1.25.3 (https://github.com/medik8s/fence-agents-remediation/blob/main/go.mod#L7)"
    }
  },
  "recommendation": {
    "classification": "Not Reachable",
    "priority": "Low",
    "action": "Vulnerable code path not called. Low priority — bump if easy, otherwise document."
  },
  "assessed_at": "2026-04-26T13:00:00Z",
  "vigil_version": "0.1.0"
}
```

### Short table output (`--short`)

Default mode combines Jira assessment with govulncheck discovery and optionally Trivy. The `SRC` column shows which scanners found each CVE, with composite labels when multiple sources agree.

```
SRC   TICKET             CVE              VERSION  LANG    STATUS               CLASSIFICATION   PRIORITY       PACKAGE                   CVSS REACHABILITY
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
J+G   RHWA-881           CVE-2026-32283   v0.4     Go(gvc) New                  Fixable Now      Critical       crypto/tls(gvc)            7.5 PACKAGE-LEVEL
Jira  RHWA-659           CVE-2026-24049   v0.6     Py(jira) Closed (Not a Bug)  Not Go           Manual         wheel(jira)                7.1 N/A
GVC   -- none --         CVE-2026-99999            Go(gvc)                      Not Reachable    Low            archive/tar(gvc)           4.2 MODULE-LEVEL (go.mod only)
Trivy -- none --         CVE-2026-35469            Go(trivy)                    Not Reachable    Low            github.com/moby/spdystr... 6.5 MODULE-LEVEL (go.mod only)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
3 assessed, 1 fixable, 1 not-go, 1 discovered (no ticket), 1 trivy-only
```

**SRC column**: `Jira` = Jira only, `GVC` = govulncheck only, `Trivy` = Trivy only, `J+G` = Jira + govulncheck, `J+T` = Jira + Trivy, `G+T` = govulncheck + Trivy, `J+G+T` = all three.

**Source annotations**: `(gvc)` = govulncheck, `(jira)` = Jira ticket data, `(trivy)` = Trivy scan.

**REACHABILITY proof**: File path for REACHABLE/TEST-ONLY, `go mod why` import chain for PACKAGE-LEVEL, `(go.mod only)` for MODULE-LEVEL.

## Classification logic

| Category | Condition | Action |
|---|---|---|
| `Fixable Now` | Reachable vuln + fix version available + downstream supports it | Bump dependency, create PR |
| `Blocked by Go` | Reachable vuln + fix needs newer Go than downstream provides | Wait for base image update |
| `Not Reachable` | Vuln in dependency but govulncheck finds no call path | Low priority, document |
| `Not Go` | Non-Go CVE (Python, C library, etc.) | Manual review |
| `Misassigned` | Wrong image (bundle) or EOL RHEL8 version | Recommend reassignment |

### Misassignment detection

- **Bundle images**: Go CVE assigned to a bundle image (OLM metadata only, no Go runtime)
- **EOL RHEL8 images**: RHEL8-based image whose OCP version has reached end-of-life

### Priority formula

Priority combines classification, CVSS severity (>=7.0 = high), and OCP support phase (GA/EUS1 = active, Maintenance/EUS2/EUS3 = lower priority).

### Color legend

Terminal output is colorized when stdout is a TTY. Use `--color` to force colors in containers.

| Element | Color | Meaning |
|---|---|---|
| Severity CRITICAL | Bright red | CVSS >= 9.0 |
| Severity HIGH | Red | CVSS >= 7.0 |
| Severity MEDIUM | Yellow | CVSS >= 4.0 |
| Severity LOW | Green | CVSS < 4.0 |
| Classification Fixable Now | Green | Fix available, act now |
| Classification Blocked by Go | Red | Needs newer Go version |
| Classification Not Reachable | Green | No call path, low risk |
| Classification Not Go | Yellow | Non-Go CVE, manual review |
| Classification Misassigned | Gray | Wrong component |
| Reachability REACHABLE | Red | Vulnerable code is called |
| Reachability other | Green | Not in call path |
| Due date overdue | Bright red | Past today |
| Due date <= 7 days | Red | Due this week |
| Due date <= 30 days | Yellow | Due this month |
| Due date > 30 days | Green | Not urgent |
| OCP tier | Bold magenta | Platform Aligned / Rolling Stream |
| OCP version | Bold cyan | OCP version number |

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `JIRA_API_TOKEN` | Yes | — | Jira API token for ticket access |
| `JIRA_EMAIL` | Yes | — | Email for Jira auth |
| `JIRA_BASE_URL` | No | `https://redhat.atlassian.net` | Jira instance URL |
| `GITLAB_TOKEN` or `GITLAB_PRIVATE_TOKEN` | No | — | GitLab token for downstream Containerfile + ARGUS skills |
| `GITLAB_HOST` | No | `https://gitlab.cee.redhat.com` | GitLab instance URL |
| `ANTHROPIC_API_KEY` | No | — | Claude API key for CVE preprocessing |

## Branch-specific scanning

When a ticket targets a specific operator version (e.g., `[far-0.4]`), vigil:
1. Creates a git worktree for the `release-0.4` branch
2. Runs govulncheck and reads go.mod from that branch
3. After the release-branch assessment, also scans `main` to report whether the CVE affects current development

## Architecture

```
vigil/
  cmd/             # Cobra CLI commands (assess, scan, check-goversion, watch)
  pkg/
    argus/         # ARGUS ProdSec skills (GitLab fetch + cache)
    assess/        # Main pipeline orchestration
    classify/      # Deterministic classification + priority logic
    cve/           # CVSS score fetching from cve.org API
    discover/      # Independent govulncheck CVE discovery
    downstream/    # Downstream Containerfile Go version fetching
    goversion/     # go.mod parsing + govulncheck runner + check-goversion
    jira/          # Jira REST API v3 + CLI client (read + writeback)
    lifecycle/     # OCP version mapping + support phase lookup
    preprocess/    # Claude CVE advisory preprocessor + cache
    report/        # Report formatting (Jira comment, sanitized summary)
    trivy/         # Trivy filesystem vulnerability scanner
    types/         # Shared types
    watch/         # Blocked CVE registry + downstream Go version monitor
```

## ARGUS ProdSec Skills Integration

Vigil v0.0.2 integrates with the [ARGUS ProdSec skills repository](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/tree/main/skills) to ensure fix PRs follow Red Hat enterprise security standards:

| Skill | What it provides |
|---|---|
| [vulnerability-management](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/blob/main/skills/secure_development/supply-chain/vulnerability-management.md) | CVE response timelines (Critical: 30d, Important: 60d, Moderate: 90d) |
| [go-security](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/blob/main/skills/secure_development/languages/go-security.md) | Go-specific: govulncheck, dependency pinning, input validation |
| [operator-security](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/blob/main/skills/secure_development/kubernetes/operator-security.md) | K8s operator RBAC, container hardening, namespace isolation |
| [differential-review](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/blob/main/skills/security_auditing/audit-workflow/differential-review.md) | Security-focused diff review for generated fix patches |
| [sast-finding-triage](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/blob/main/skills/secure_development/rh-secure-sdlc/sast/sast-finding-triage.md) | SARIF parsing, true/false positive determination |
| [supply-chain-risk-auditor](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/blob/main/skills/secure_development/supply-chain/supply-chain-risk-auditor.md) | Dependency health: maintainer risk, CVE history |
| [container-hardening](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/blob/main/skills/secure_development/kubernetes/container-hardening.md) | Container image hardening guidance |

## Status

v0.0.2 — extends the triage pipeline from v0.0.1 with three detection sources, watch mode, and Jira writeback. Piloted on Fence Agents Remediation ([RHWA-922](https://redhat.atlassian.net/browse/RHWA-922)). Supports all 7 medik8s components: FAR, SNR, NHC, NMO, MDR, SBR, and NHC-CONSOLE.

### What's new in v0.0.2

- **Trivy** as third detection source alongside Jira + govulncheck (composite source tracking: J+G, J+T, G+T)
- **`vigil watch`** — monitor blocked CVEs, promote when downstream Go version updates
- **`vigil check-goversion`** — check downstream base image Go version availability
- **Jira writeback** — transition tickets, link PRs, add labels via REST API
- **ARGUS ProdSec skills** — fetch Go security, vulnerability management, and operator security skills from GitLab
- **Claude CVE preprocessor** — offline advisory digestion with local caching
- **RH CA certs** in container image for `gitlab.cee.redhat.com` TLS

### Roadmap

See [docs/design-v0.0.2.md](docs/design-v0.0.2.md) and [docs/plan-v0.0.2.md](docs/plan-v0.0.2.md).

**Pending for v0.0.2:**
- `vigil fix` — automated fix PRs with 4 Go patching strategies (direct → transitive → replace → major bump)
- Intelligent routing (deterministic fix vs AI-assisted workflow)

**v0.0.3 Preview:**
- Snyk integration ([RHWA-632](https://redhat.atlassian.net/browse/RHWA-632))
- Agentic mode — detection agent + fix agent running independently
