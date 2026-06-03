# Vigil

[GitHub](https://github.com/razo7/vigil) | [Container images](https://quay.io/repository/oraz/vigil)

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
vigil scan --component FAR --short
       │
       ├─ Phase 1: Jira assessment
       │    └─ For each CVE ticket → run full assess pipeline
       │
       ├─ Phase 2: govulncheck discovery
       │    ├─ Run govulncheck once on the operator repo
       │    ├─ Cross-reference findings against Jira tickets
       │    └─ Flag untracked vulnerabilities (SRC=GVC)
       │
       ├─ Phase 3: Trivy scan (enabled by default, --trivy=false to disable)
       │    ├─ Run trivy fs on the operator repo
       │    ├─ Deduplicate against Jira + govulncheck findings
       │    └─ Flag Trivy-only vulnerabilities (SRC=Trivy)
       │
       └─ Phase 4: Combined output
            ├─ Merge all sources (SRC: Jira/GVC/Trivy/J+G/J+T/G+T/J+G+T)
            ├─ Record blocked CVEs to watch registry
            └─ Sort by source → status → priority → reachability → CVSS
```

## Quick start (container — recommended)

The container image is the preferred way to run Vigil. It bundles the exact Go toolchain, govulncheck, Trivy, jira CLI, skopeo, and git — ensuring deterministic, reproducible results across all users and environments.

```bash
podman pull quay.io/oraz/vigil:latest

# Scan a component
podman run --rm -t \
  -e JIRA_API_TOKEN=$JIRA_API_TOKEN \
  -e JIRA_EMAIL=$JIRA_EMAIL \
  -e GITLAB_PRIVATE_TOKEN=$GITLAB_PRIVATE_TOKEN \
  quay.io/oraz/vigil:latest scan --component FAR --short

# Assess a single ticket
podman run --rm -t \
  -e JIRA_API_TOKEN=$JIRA_API_TOKEN \
  -e JIRA_EMAIL=$JIRA_EMAIL \
  -e GITLAB_PRIVATE_TOKEN=$GITLAB_PRIVATE_TOKEN \
  quay.io/oraz/vigil:latest assess RHWA-881

# With a custom config file
podman run --rm -t \
  -e JIRA_API_TOKEN=$JIRA_API_TOKEN \
  -e JIRA_EMAIL=$JIRA_EMAIL \
  -v ./my-vigil.yaml:/config.yaml:ro \
  quay.io/oraz/vigil:latest scan --component myop --config /config.yaml --short
```

Red Hat IT Root CA certificates are embedded for `gitlab.cee.redhat.com` access. The jira CLI is auto-configured at startup from `JIRA_EMAIL`.

### Build the container locally

```bash
make docker-build
```

### Install from source (advanced)

Only needed for development. You must separately install govulncheck, Trivy, and skopeo.

```bash
make install
```

## Usage

All examples below use `vigil` as shorthand. In production, prefer the container form:

```bash
alias vigil='podman run --rm -t \
  -e JIRA_API_TOKEN=$JIRA_API_TOKEN \
  -e JIRA_EMAIL=$JIRA_EMAIL \
  -e GITLAB_PRIVATE_TOKEN=$GITLAB_PRIVATE_TOKEN \
  quay.io/oraz/vigil:latest'
```

### Assess a single ticket

```bash
vigil assess RHWA-881
vigil assess RHWA-881 --jira              # post result as Jira comment
vigil assess RHWA-881 --commit abc1234    # pin to specific commit
```

### Batch scan all tickets for a component

```bash
vigil scan --component FAR --short
vigil scan --component FAR --short --include-closed   # include closed tickets
vigil scan --component FAR --short --include-bugs      # include non-CVE bugs
vigil scan --component FAR --short --since 1w          # last week only
vigil scan --component FAR --short --commit abc1234    # pin to specific commit
vigil scan --component FAR --fix                       # auto-fix Fixable Now
vigil scan --component FAR --fix --dry-run             # preview fixes
vigil scan --component FAR --go-version 1.25.9         # skip GitLab token
vigil scan --component FAR --jira --summary-file vigil-summary.json
```

### HTML report (colored, browser-friendly)

```bash
vigil scan --component FAR --format html > far-report.html
xdg-open far-report.html
```

Produces a standalone HTML file with colored classification/priority badges, clickable Jira and CVE links, sticky headers, and hover highlighting. The terminal `--short` output uses ANSI colors; `--format html` preserves the same color scheme for browsers.

**Classification decision tree** (based on ProdsecTeam CVE assessment policies):

```
1. Is the vulnerable code present in the product?
   ├─ No → 🟢 Close (code doesn't exist)
   └─ Yes ↓

2. Is it a Go CVE?
   ├─ No → ❓ Unknown (manual review)
   └─ Yes ↓

3. Is the image a bundle (OLM metadata)?
   ├─ Yes + Go CVE → ↩️ Misassigned (no Go runtime in bundle)
   ├─ Yes + non-Go → ❓ Unknown (check if bundle uses it)
   └─ No ↓

4. Is the operator version EOL?
   ├─ Yes → ↩️ EOL (no fix required)
   └─ No ↓

5. Is the code reachable? (govulncheck + fix-function match)
   ├─ Not imported → 🟢 No action
   ├─ Module-level only → 🟢 No action (go.mod only)
   ├─ Package imported but fix functions not called
   │   → 🟢 Affected but not Impacted (close with justification)
   └─ Reachable or package-level ↓

6. Is the fix deployable? (downstream Go version check)
   ├─ Needs newer Go → 🟠⏳ Blocked (needs Go X.Y.Z)
   └─ Deployable ↓

7. Does the CVE qualify for this version's lifecycle phase?
   ├─ Full Support → fix all Critical + Important
   ├─ Maintenance / EUS → fix ONLY if RH rates Critical or Important
   │   (upstream rating irrelevant if RH downgrades to Moderate/Low)
   └─ EOL → no fix ↓

8. Which supported versions are affected?
   └─ 🔴🔧 Fix on v0.4 (Full Support), v0.6 (EUS)
```

Lifecycle phases (from https://access.redhat.com/support/policy/updates/openshift#ocp):

| Phase | Duration | Fixes Required |
|-------|----------|---------------|
| Full Support | 0–6 months from GA | All qualified Critical + Important |
| Maintenance | 6–18 months | Critical + Important ONLY |
| EUS Term 1 | 18–24 months | Critical + Important backports |
| EUS Term 2 | 24–36 months | Critical + Important backports |
| EUS Term 3 | 36–48 months | Critical + Important backports |

**Color legend:**

| Emoji | ACTION | Meaning |
|-------|--------|---------|
| 🔴🔧 | Fix on v0.2, v0.4 | Specific versions needing fix |
| 🟠⏳ | Blocked (Go X.Y.Z) | Fix needs newer Go than downstream |
| 🟢 | No action | Not reachable / not imported |
| ❓ | Manual review | Non-Go or ambiguous CVE |
| ↩️ | Misassigned / EOL | Wrong target or unsupported version |

| Emoji | Reachability | Meaning |
|-------|-------------|---------|
| 🎯 | REACHABLE | govulncheck confirmed call path to vulnerable function |
| 🧪 | TEST-ONLY | Reachable only in test code |
| 📦 | PACKAGE-LEVEL | Package imported but no direct call path |
| 📋 | MODULE-LEVEL | In go.mod only, package not imported |
| 🚫 | NOT-IMPORTED | Affected package not imported at all |

See [docs/v0.0.4/action-column-design.md](docs/v0.0.4/action-column-design.md) for full design.

### Custom Jira instance

```bash
vigil scan --component myop --config my-vigil.yaml --short
```

Where `my-vigil.yaml` defines your Jira projects and components (see `rhwa_jira_example.yaml`).

Supported components (default config): `FAR`, `SNR`, `NHC`, `NMO`, `MDR`, `SBR`, `NHC-CONSOLE`.

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
SRC   TICKET             CREATED    CVE              VERSION  LANG       STATUS               CLASSIFICATION   PRIORITY       PACKAGE                      CVSS REACHABILITY
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
J+G   RHWA-881           2026-04-13 CVE-2026-32283   v0.4     Go(gvc)    New                  Fixable Now      Critical       crypto/tls(gvc)               7.5 PACKAGE-LEVEL
Jira  RHWA-659           2026-02-01 CVE-2026-24049   v0.6     Py(jira)   Closed (Not a Bug)   Not Go           Manual         wheel(jira)                   7.1 N/A
GVC   -- none --                    CVE-2026-99999            Go(gvc)                         Not Reachable    Low            archive/tar(gvc)              4.2 MODULE-LEVEL (go.mod only)
Trivy -- none --                    CVE-2026-35469            Go(trivy)                       Not Reachable    Low            github.com/moby/spdystr...    6.5 MODULE-LEVEL (go.mod only)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
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
    argus/         # ARGUS ProdSec skills (GitHub + GitLab fetch + cache)
    config/        # YAML config loader + hardcoded defaults
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

Vigil integrates with the [ARGUS ProdSec skills repository](https://github.com/RedHatProductSecurity/prodsec-skills) (public, 138 skills) to ensure fix PRs follow Red Hat enterprise security standards. Falls back to [internal GitLab](https://gitlab.cee.redhat.com/product-security/prodsec-skills/) when available:

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
- **Jira CLI** in container image, auto-configured from `JIRA_EMAIL`
- **`--include-bugs`** — filter non-CVE Bug tickets from scan results
- **`--fix`** — auto-fix Fixable Now tickets with `vigil fix` pipeline
- **CREATED column** in `--short` table output (Jira ticket creation date)
- **UPDATED column** in `--short` table output (Jira last-modified date for staleness tracking)
- **Go toolchain** in container for govulncheck source-level analysis
- **`--config`** — optional YAML config file to define components, operators, and repos (see `vigil.yaml.example`)
- **`--commit`** — pin repo checkout to a specific commit SHA for point-in-time analysis
- **ARGUS dual sources** — fetch ProdSec skills from [public GitHub](https://github.com/RedHatProductSecurity/prodsec-skills) (no auth), fall back to internal GitLab
- **`--format html`** — colored HTML report with badges, clickable links, sticky headers (open in browser)
- **`--go-version`** — specify downstream Go version directly, skip GitLab Containerfile fetch
- **Fix-function reachability** — downgrade to Not Reachable when fix CL functions are not called by the operator
- **Jira project/URL configurable** — `jira.base_url` and `jira.projects` in config, not hardcoded to RHWA/ECOPROJECT
- **OCP lifecycle in config** — operator→OCP version mappings movable to YAML (no code change needed for new versions)

### What's new in v0.0.3

- **`vigil reachability`** — multi-signal analysis per release branch (govulncheck + fix-function match + OCP lifecycle) with backport verdict
- **Intelligent routing** — routes CVEs to DependencyBump, GoMinor, SemanticFix, or Manual based on package type and fix version
- **Agentic pipe protocol** — `vigil scan --detect-only | vigil fix --batch` for decoupled detection + fixing
- **Terminal dashboard** — compact summary with classification/reachability counts and top 5 action items after scan
- **ASCII call-path trees** — REACHABLE CVEs show call chain from operator code to vulnerable function
- **Two-tier HTML reports** — summary page with SVG donut chart + severity bar + sortable table; verbose page with mermaid call-path diagrams
- **`--security-review`** on fix — checks diffs for replace directives, version downgrades, new deps, removed crypto imports
- **Variant analysis** — after fix, scans for remaining CVEs in the same package
- **Security warnings in PRs** — diff review findings included in PR descriptions

### Roadmap

See [docs/v0.0.3/plan.md](docs/v0.0.3/plan.md).

**v0.0.4 Preview:**
- Multi-branch CVE discovery — scan all supported release branches/tags, not just main
- Container health index integration — fetch grades from catalog.redhat.com or other scanners
- Consolidated ACTION column — merge classification + backport into version-specific directives
- Third-party fix-function detection via GitHub API (extend Gerrit CL analysis beyond stdlib)
- Snyk integration ([RHWA-632](https://redhat.atlassian.net/browse/RHWA-632))
- Konflux Conforma results as input source for component state
- Multi-branch reachability comparison (`vigil reachability --component far --version 0.2,0.4`)
- ExploitIQ reachability oracle for ambiguous CVEs

See [docs/v0.0.4/action-column-design.md](docs/v0.0.4/action-column-design.md) for full design.
