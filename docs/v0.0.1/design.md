# Vigil v0.0.1 — MVP Design

Deterministic CVE assessment tool for [medik8s](https://github.com/medik8s) operators.

## Problem

Each medik8s operator accumulates CVE tickets faster than the team can manually triage. Most are non-issues: wrong component, unreachable code, non-Go CVEs on Go operators, or EOL versions. The FAR pilot found 92 of 100 closed SecurityTracking tickets resolved as "Not a Bug."

Manual triage per ticket takes 15–30 minutes: open Jira, find the CVE, check if it's Go, check govulncheck, look up the Go version, check downstream, decide priority. Vigil replaces this with a single command.

## Goals (v0.0.1 MVP)

1. Assess a single CVE ticket end-to-end: `vigil assess RHWA-123`
2. Batch scan all open tickets for a component: `vigil scan --component FAR --short`
3. Classify every CVE into one of 5 actionable categories
4. Assign deterministic priority based on severity, reachability, and support phase
5. Detect misassigned tickets (bundle images, EOL RHEL8)
6. Output structured JSON (machine-readable) and colorized terminal output (human-readable)
7. Optionally post assessment as Jira comment

## Non-goals (v0.0.1)

- Automated fix PR creation (future: Claude Code skill)
- Weekly Go version crawler (future: GitHub Actions cron)
- Interactive UI or dashboard
- Support for non-medik8s operators

## Architecture

```
vigil assess RHWA-123
       │
       ├── Jira (REST API + CLI) ─── ticket metadata, CVE ID, component
       ├── CVE.org API ───────────── CVSS score, description, CWE
       ├── govulncheck ──────────── reachability, call paths, fix version
       ├── go.mod ───────────────── current Go version
       ├── GitLab API ───────────── downstream Containerfile Go version
       ├── Go Review (Gerrit) ───── fix-function extraction from CLs
       ├── OSV API ──────────────── affected version ranges (fallback)
       ├── Skopeo ───────────────── downstream container image tags
       └── Lifecycle tables ─────── operator→OCP→support phase mapping
              │
              ▼
       Classification + Priority + Recommendation
              │
              ├── stdout (JSON or table)
              └── Jira comment (--jira flag)
```

### Package layout

```
vigil/
  cmd/
    root.go             Cobra root command, --color flag
    assess.go           Single ticket assessment
    scan.go             Batch scan with --short table output
    check_goversion.go  Go version availability check (stub)
    output.go           JSON colorization and terminal formatting
  pkg/
    assess/             Pipeline orchestration
      assess.go         Main Run() pipeline (10-step flow)
      repo.go           Git clone and worktree management
      gerrit.go         Gerrit CL fix-function extraction
      vulndb.go         OSV API fallback for version ranges
    classify/           Deterministic classification logic
      classify.go       Decision tree + priority formula
      version.go        Semantic version comparison
    cve/                CVE.org API client
      cve.go            CVSS score and metadata fetching
    downstream/         Downstream base image integration
      containerfile.go  GitLab Containerfile Go version extraction
      skopeo.go         Container registry tag lookup
    goversion/          Go toolchain analysis
      gomod.go          go.mod parsing (min version, toolchain)
      vulncheck.go      govulncheck JSON parser
      worktree.go       Git worktree operations
    jira/               Jira integration
      client.go         REST API v3 + CLI search
    lifecycle/          OCP lifecycle data
      lifecycle.go      Operator→OCP mapping, support phase lookup
    report/             Output formatting
      report.go         Jira comment and sanitized summary
    types/              Shared type definitions
      types.go          Classification, Priority, SupportPhase, Result
```

## Classification Decision Tree

```
Input: ticket metadata + govulncheck + downstream Go version + CVSS + support phase

1. Is it a bundle image or EOL RHEL8?
   └─ yes → MISASSIGNED (priority: Misassigned)

2. Is it a Go CVE?
   └─ no → NOT GO (priority: Manual)

3. Is the vulnerable code reachable or package-level?
   └─ no (module-level only) → NOT REACHABLE (priority: Low)

4. Does the fix require a newer Go than downstream provides?
   └─ yes → BLOCKED BY GO (priority: f(reachable, CVSS, phase))

5. Otherwise → FIXABLE NOW (priority: f(CVSS, phase))
```

### Reachability levels

govulncheck reports three levels. Vigil adds two refinements:

| Level | Meaning | How detected |
|---|---|---|
| REACHABLE | Function call path from binary entry point to vulnerable code | govulncheck finding with function frames |
| TEST-ONLY | Call path exists but only through test/e2e code | All call path endpoints are in `_test.go`, `/test/`, `/e2e/` |
| PACKAGE-LEVEL | Package imported but no call path to vulnerable function | govulncheck finding with package frame only |
| MODULE-LEVEL | Module in go.mod but vulnerable package not imported | govulncheck finding with module frame only |
| UNKNOWN | CVE not in Go vulnerability database | No govulncheck match for CVE aliases |

**Fix-function cross-reference:** When govulncheck reports REACHABLE, Vigil fetches the Gerrit CL that fixed the vulnerability, extracts the modified functions, and checks if any appear in the call paths. If none match, the vuln is downgraded to PACKAGE-LEVEL. This implements the team's 3-step triage: (1) check Go version, (2) check backport, (3) check specific fix functions.

### Priority formula

Priority is deterministic, combining CVSS severity and OCP support phase:

**For Fixable Now:**

| CVSS | Active (GA/EUS1) | Later (Maintenance/EUS2/EUS3) |
|---|---|---|
| >= 7.0 | Critical | High |
| < 7.0 | High | Medium |

**For Blocked by Go:**

| Reachable? | CVSS | Active? | Priority |
|---|---|---|---|
| yes | >= 7.0 | yes | Critical |
| yes | >= 7.0 | no | High |
| yes | any | yes | High |
| otherwise | any | any | Low |

**Fixed priorities:** Not Reachable → Low, Not Go → Manual, Misassigned → Misassigned.

### Misassignment detection

1. **Bundle images:** Image name contains "bundle" or "-metadata" → OLM metadata only, no Go runtime
2. **EOL RHEL8 images:** Image name contains "rhel8"/"rhel-8" AND OCP support phase is EOL

## Data sources

| Source | What | How |
|---|---|---|
| Jira | Ticket metadata, CVE ID, component, operator version | REST API v3 (Basic auth) for single tickets; `jira` CLI for search (supports ECOPROJECT) |
| cve.org | CVSS score, severity, description, CWE, references | `https://cveawg.mitre.org/api/cve/{id}` |
| govulncheck | Reachability, call paths, fix version, vuln ID | `govulncheck -json ./...` (shelled out) |
| go.mod | Current Go version (min version + toolchain) | Parsed from repo |
| GitLab | Downstream Containerfile Go version | API v4 raw file endpoint |
| Go Review | Fix-function names from patches | Gerrit base64 patch API |
| OSV | Affected version ranges, references | `https://api.osv.dev/v1/vulns/{id}` |
| Skopeo | Container image tags for downstream component lookup | `skopeo list-tags` |
| Lifecycle tables | Operator version → OCP version → support phase | Hardcoded from Red Hat support matrix |

## CLI interface

### `vigil assess <TICKET-ID>`

Assess a single CVE ticket. Outputs full JSON to stdout.

```
Flags:
  --jira              Post assessment as Jira comment
  --summary-file PATH Write sanitized summary (no CVE IDs) to file
  --repo-path PATH    Path or URL to operator repo (auto-detected if omitted)
  --color             Force colored output
```

### `vigil scan --component <NAME>`

Batch assess all open CVE tickets for a component. Uses `jira` CLI for search (can access both RHWA and ECOPROJECT projects).

```
Flags:
  --component NAME    Component: FAR, SNR, NHC, NMO, MDR
  --jql QUERY         Custom JQL (overrides --component)
  --short             Compact summary table instead of full JSON
  --include-closed    Include closed tickets
  --jira              Post each assessment as Jira comment
  --summary-file PATH Write aggregate summary
  --repo-path PATH    Path to operator repo
  --color             Force colored output
```

Short table output:
```
TICKET             VERSION  CLASSIFICATION   PRIORITY        CVSS REACHABILITY   PACKAGE
─────────────────────────────────────────────────────────────────────────────────────────
RHWA-881           v0.4     Blocked by Go    Low              7.5 TEST-ONLY      crypto/tls
ECOPROJECT-2468    v0.4     Fixable Now      High             5.3 PACKAGE-LEVEL  golang.org/x/net/html
RHWA-659           v0.6     Not Go           Manual           7.1 N/A            unknown
─────────────────────────────────────────────────────────────────────────────────────────
3 assessed, 1 fixable, 1 blocked, 1 not-go
```

### `vigil check-goversion` (stub)

Not yet implemented. Will check if a desired Go version is available in downstream base images.

## Output formats

### Full JSON (default)

Structured result with four top-level sections:

```json
{
  "source": {
    "ticket_id": "RHWA-811 (https://redhat.atlassian.net/browse/RHWA-811)",
    "affected operator version": "fence-agents-remediation:v0.4",
    "reporter": "...",
    "assignee": "...",
    "due_date": "2026-04-20",
    "affects_rhwa_versions": "rhwa-24.2",
    "rhwa-ocp_support": ["Platform Aligned OCP 4.16: EUS1 until ..."]
  },
  "vulnerability": {
    "cve_id": "CVE-2026-27137 (https://www.cve.org/CVERecord?id=...)",
    "severity": 7.5,
    "severity_label": "HIGH",
    "vuln_id": "GO-2026-4599",
    "package": "crypto/x509",
    "fix_version": "1.26.1 (https://go-review.googlesource.com/...)",
    "fix_functions": "constraints.go:query, constraints.go:checkConstraints",
    "affected_go_versions": ">= 1.26.0-0, < 1.26.1 (https://pkg.go.dev/vuln/...)"
  },
  "analysis": {
    "release_branch": {
      "reachability": "TEST-ONLY (reachable only through test code, not shipped binary)",
      "upstream": { "branch": "release-0.4", "go_version": "1.20" },
      "downstream": { "branch": "far-0-4", "go_version": "1.20.12" },
      "call_paths": ["*Conn.Read (conn.go) → Fetch (fetch_test.go)"]
    },
    "fix_upstream?": {
      "reachability": "TEST-ONLY (reachable only through test code, not shipped binary)",
      "go_version": "1.25.3"
    }
  },
  "recommendation": {
    "classification": "Not Reachable",
    "priority": "Low",
    "action": "Vulnerable code path not called. Low priority — bump if easy, otherwise document."
  }
}
```

### Jira comment

Text-based report posted as a code block comment. Includes all fields from JSON in human-readable format.

### Sanitized summary

Minimal JSON without CVE IDs, safe for public repos. Includes classification counts and Go version info.

## Pipeline flow (assess)

```
1. Fetch Jira ticket → extract CVE ID, component, operator version, image name
2. Derive operator name and repo URL from Jira component
3. Resolve repo path (clone if URL, use local if path, auto-detect if omitted)
4. If ticket targets a specific version:
   a. Create git worktree for release-X.Y branch
   b. Scan from worktree
5. Read go.mod → current Go version (min version or toolchain)
6. Run govulncheck -json ./... → parse all findings
7. Collect ALL unique call paths (not just longest)
8. Detect test-only paths (all endpoints in test files)
9. Fetch CVSS score from cve.org → severity + description + references
10. Fetch downstream Go version from GitLab Containerfile
11. Map operator version → OCP version → support phase
12. If reachable: fetch Gerrit CL, extract fix functions, cross-reference call paths
13. Classify (decision tree) + assign priority (formula)
14. If worktree was used: also scan main branch for comparison
15. Generate recommendation text
16. Output JSON (+ optional Jira comment)
```

## Operator coverage

All 5 medik8s operators supported:

| Short | Operator | Upstream repo |
|---|---|---|
| FAR | fence-agents-remediation | github.com/medik8s/fence-agents-remediation |
| SNR | self-node-remediation | github.com/medik8s/self-node-remediation |
| NHC | node-healthcheck-controller | github.com/medik8s/node-healthcheck-operator |
| NMO | node-maintenance-operator | github.com/medik8s/node-maintenance-operator |
| MDR | machine-deletion-remediation | github.com/medik8s/machine-deletion-remediation |

Downstream repos at `gitlab.cee.redhat.com/dragonfly/<operator>`.

## OCP lifecycle mapping

Hardcoded from [Red Hat support policy](https://access.redhat.com/support/policy/updates/openshift_operators#platform-aligned). Covers OCP 4.12–4.21 with support phase dates (GA, EUS1, Maintenance, EUS2, EUS3, EOL).

Each operator version maps to one or more OCP versions. Example:
- FAR 0.4 → OCP 4.16
- FAR 0.6 → OCP 4.16, 4.17, 4.18, 4.19, 4.20

## Environment variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `JIRA_API_TOKEN` | yes | — | Jira authentication |
| `JIRA_EMAIL` | yes | — | Jira authentication |
| `JIRA_BASE_URL` | no | `https://redhat.atlassian.net` | Jira instance |
| `GITLAB_TOKEN` / `GITLAB_PRIVATE_TOKEN` | no | — | Downstream Containerfile access |
| `GITLAB_HOST` | no | `https://gitlab.cee.redhat.com` | GitLab instance |

Also requires `govulncheck`, `git`, and optionally `skopeo` and `jira` CLI on PATH.

## Dependencies

- Go 1.25.8
- `github.com/spf13/cobra` — CLI framework
- `golang.org/x/term` — TTY detection for colorized output
- No LLM, no AI — every classification decision is codified in Go

## Known limitations (v0.0.1)

1. **Lifecycle data is hardcoded** — operator→OCP mappings and OCP release dates are in Go source. Future: fetch from support matrix API.
2. **ECOPROJECT REST API inaccessible** — the Jira REST API cannot query ECOPROJECT (returns empty). Scan uses the `jira` CLI as workaround, falling back to REST API.
3. **govulncheck shelled out** — runs `govulncheck -json ./...` as subprocess rather than using the Go API. Works but requires govulncheck on PATH.
4. **No automatic fix PRs** — classification is automated, remediation is manual. Future: Claude Code skill wraps Vigil and offers fix PRs for fixable-now CVEs.
5. **check-goversion not implemented** — stub only. Future: weekly cron checks if downstream base image has been updated.
6. **Single-repo scan** — batch scan reuses the same repo for all tickets of a component. Cross-component or multi-repo scans not supported.
