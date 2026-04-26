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
podman run --rm -e JIRA_API_TOKEN=$JIRA_API_TOKEN vigil assess RHWA-881
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
  "ticket_id": "RHWA-881",
  "cve_id": "CVE-2026-32283",
  "cve_source": "https://www.cve.org/CVERecord?id=CVE-2026-32283",
  "severity": 7.5,
  "severity_label": "HIGH",
  "package": "crypto/tls",
  "classification": "misassigned",
  "priority": "Misassigned",
  "operator_version": "0.4",
  "ocp_version": "4.16",
  "support_phase": "EUS2",
  "reachability": "REACHABLE",
  "vuln_id": "GO-2026-4870",
  "fix_version": "1.25.9",
  "current_go": "1.20",
  "downstream_go": "1.20",
  "call_path": "*Conn.HandshakeContext -> ... -> *Request.Stream -> GetLogs",
  "recommendation": "Ticket appears misassigned: CVE targets RHEL8-based image for unsupported operator version.",
  "main_branch": {
    "reachability": "REACHABLE",
    "vuln_id": "GO-2026-4870",
    "fix_version": "1.25.9",
    "current_go": "1.25.3",
    "package": "crypto/tls"
  }
}
```

## Classification logic

| Category | Condition | Action |
|---|---|---|
| `fixable-now` | Reachable vuln + fix version available + downstream supports it | Bump dependency, create PR |
| `blocked-by-go` | Reachable vuln + fix needs newer Go than downstream provides | Wait for base image update |
| `not-reachable` | Vuln in dependency but govulncheck finds no call path | Low priority, document |
| `not-go` | Non-Go CVE (Python, C library, etc.) | Manual review |
| `misassigned` | Wrong image (bundle) or unsupported version (RHEL8) | Recommend reassignment |

### Misassignment detection

- **Bundle images**: Go CVE assigned to a bundle image (OLM metadata only, no Go runtime)
- **RHEL8 thresholds**: Old operator versions below the RHEL8-to-RHEL9 transition:
  - FAR < 0.5.0, SNR < 0.10.0, NHC < 0.9.0, NMO < 5.4.0, MDR < 0.4.0

### Priority formula

Priority combines classification, CVSS severity (>=7.0 = high), and OCP support phase (GA/EUS1 = active, Maintenance/EUS2/EUS3 = lower priority).

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `JIRA_API_TOKEN` | Yes | — | Jira API token for ticket access |
| `JIRA_EMAIL` | No | `oraz@redhat.com` | Email for Jira auth |
| `JIRA_BASE_URL` | No | `https://redhat.atlassian.net` | Jira instance URL |
| `GITLAB_TOKEN` | No | — | GitLab token for downstream Containerfile access |
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
