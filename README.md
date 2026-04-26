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

## Install

```bash
go install github.com/razo7/vigil@latest

# Requires govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest
```

### Container

```bash
podman build -t vigil -f Containerfile .
podman run --rm -t \
  -e JIRA_API_TOKEN=$JIRA_API_TOKEN \
  -e GITLAB_PRIVATE_TOKEN=$GITLAB_PRIVATE_TOKEN \
  vigil assess RHWA-881
```

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
vigil scan --component FAR
vigil scan --component SNR --repo-path /path/to/self-node-remediation
vigil scan --component FAR --jira --summary-file vigil-summary.json
```

Supported components: `FAR`, `SNR`, `NHC`, `NMO`, `MDR`.

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
| `GITLAB_TOKEN` or `GITLAB_PRIVATE_TOKEN` | No | — | GitLab token for downstream Containerfile access |
| `GITLAB_HOST` | No | `https://gitlab.cee.redhat.com` | GitLab instance URL |

## Branch-specific scanning

When a ticket targets a specific operator version (e.g., `[far-0.4]`), vigil:
1. Creates a git worktree for the `release-0.4` branch
2. Runs govulncheck and reads go.mod from that branch
3. After the release-branch assessment, also scans `main` to report whether the CVE affects current development

## Architecture

```
vigil/
  cmd/             # Cobra CLI commands (assess, scan, check-goversion)
  pkg/
    assess/        # Main pipeline orchestration
    classify/      # Deterministic classification + priority logic
    cve/           # CVSS score fetching from cve.org API
    downstream/    # Downstream Containerfile Go version fetching
    goversion/     # go.mod parsing + govulncheck runner
    jira/          # Jira REST API v3 client
    lifecycle/     # OCP version mapping + support phase lookup
    report/        # Report formatting (Jira comment, sanitized summary)
    types/         # Shared types
```

## Status

POC — piloted on Fence Agents Remediation (RHWA-922). Designed for all 5 medik8s operators.
