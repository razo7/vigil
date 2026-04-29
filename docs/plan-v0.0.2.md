# Plan: Vigil v0.0.2 — Full Implementation

## Context

Vigil v0.0.1 is a deterministic Go CLI that triages CVE tickets but doesn't fix them. RHWA-921 requires a full triage-to-fix pipeline. We researched 5 tools and identified 6 architectural recommendations. The user wants all 6 implemented + Trivy as a third detection source, split into logical commits.

## What Changes

1. **Version bump** — 0.0.1 → 0.0.2 in Makefile and code
2. **Fix pipeline** — new `vigil fix` command with 4 Go patching strategies (direct, transitive, replace, major bump) in risk-ascending cascade
3. **`--fix` flag** on existing assess/scan commands
4. **PR creation** — draft PRs via `gh pr create --draft`
5. **Jira bidirectional sync** — writeback (link PR, post status comment)
6. **Watch mode** — `vigil watch` monitors blocked CVEs, re-checks when downstream Go updates
7. **check-goversion** — implement the existing stub
8. **Trivy integration** — third detection source in scan mode + added to Containerfile
9. **Intelligent routing** — route to fix pipeline or output AI-workflow instructions based on CVE type
10. **ARGUS ProdSec skills** — fetch from GitLab, include guidance in PR descriptions
11. **Claude preprocessor** — offline CVE advisory digestion, cached per CVE
12. **CI** — Makefile VERSION=0.0.2, Containerfile adds trivy + gh CLI
13. **README** — full update with ARGUS skill links, new commands, architecture
14. **Design doc** — update with ARGUS skill links and full pipeline

## ARGUS ProdSec Skills (relevant to Vigil)

Base URL: https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/blob/main/

| Skill | Path | Relevance to Vigil |
|---|---|---|
| **vulnerability-management** | `skills/secure_development/supply-chain/vulnerability-management.md` | Core — CVE response timelines, triage→patch→release process |
| **go-security** | `skills/secure_development/languages/go-security.md` | Core — Go-specific: govulncheck, dependency pinning, input validation |
| **operator-security** | `skills/secure_development/kubernetes/operator-security.md` | Core — K8s operator RBAC, container hardening, namespace isolation |
| **differential-review** | `skills/security_auditing/audit-workflow/differential-review.md` | Fix PRs — security-focused diff review for generated patches |
| **sast-finding-triage** | `skills/secure_development/rh-secure-sdlc/sast/sast-finding-triage.md` | Triage — SARIF parsing, true/false positive determination |
| **supply-chain-risk-auditor** | `skills/secure_development/supply-chain/supply-chain-risk-auditor.md` | Dependencies — dependency health, maintainer risk, CVE history |
| **container-hardening** | `skills/secure_development/kubernetes/container-hardening.md` | Containerfile — hardening guidance for Vigil's own image |

## Commit Sequence (17 commits, 6 phases)

### Phase 1: Foundation (commits 1–2)

**Commit 1: Bump version to 0.0.2**
- `Makefile` — `VERSION ?= 0.0.2`
- `pkg/assess/assess.go:22` — `version = "0.2.0"`
- Verify: `make build && ./bin/vigil assess --help`

**Commit 2: Implement check-goversion command**
- `cmd/check_goversion.go` — replace stub with full implementation
- NEW `pkg/goversion/check.go` — `CheckGoVersion()` reusing `downstream.FetchGoVersionForOperator()` and `classify.CompareVersions()`
- NEW `pkg/goversion/check_test.go`
- Verify: `./bin/vigil check-goversion --operator FAR --want 1.25.9`

### Phase 2: Fix Pipeline (commits 3–7)

**Commit 3: Add fix strategy interface and validation**
- NEW `pkg/fix/strategy.go` — `Strategy` interface, `StrategyOptions`, `StrategyResult`
- NEW `pkg/fix/validate.go` — validation pipeline: go mod tidy → govulncheck → go build → go test
- NEW `pkg/fix/rollback.go` — backup/restore go.mod + go.sum
- NEW tests for each

**Commit 4: Implement 4 fix strategies**
- NEW `pkg/fix/direct.go` — `go get pkg@fix-version` (risk 1)
- NEW `pkg/fix/transitive.go` — find parent via `go mod graph`, bump parent (risk 2)
- NEW `pkg/fix/replace.go` — `go mod edit -replace` (risk 3)
- NEW `pkg/fix/major.go` — major version bump, requires `--approve-major` (risk 4)
- NEW tests for each

**Commit 5: Add fix orchestrator with cascade logic**
- NEW `pkg/fix/fix.go` — `Run()` iterates strategies in order, validates after each, rolls back on failure
- NEW `pkg/fix/fix_test.go`

**Commit 6: Add fix command and --fix flag**
- NEW `cmd/fix.go` — `vigil fix <TICKET-ID>` with flags: `--strategy`, `--dry-run`, `--jira`, `--approve-major`, `--repo-path`
- MODIFY `cmd/assess.go` — add `--fix` flag, run fix pipeline if Fixable Now
- MODIFY `cmd/scan.go` — add `--fix` flag, run fix pipeline for each Fixable Now result

**Commit 7: Add PR creation package**
- NEW `pkg/pr/pr.go` — `Create()`: git branch → commit → push → `gh pr create --draft`
- NEW `pkg/pr/description.go` — PR body template (CVE, strategy, validation results)
- NEW `pkg/pr/pr_test.go`
- MODIFY `pkg/fix/fix.go` — call `pr.Create()` after successful fix
- MODIFY `cmd/fix.go` — add `--pr` flag (default true)

### Phase 3: Jira + Watch Mode (commits 8–11)

**Commit 8: Add Jira writeback (transitions, PR linking)**
- MODIFY `pkg/jira/client.go` — add `TransitionTicket()`, `LinkPR()`, `AddLabel()`, `GetTransitions()`
- NEW `pkg/jira/transitions.go` — transition types
- NEW `pkg/jira/transitions_test.go`
- MODIFY `pkg/fix/fix.go` — after PR, call `jira.LinkPR()` and post comment

**Commit 9: Add artifact trail for fix phases**
- NEW `pkg/fix/artifacts.go` — `ArtifactTrail` writes JSON per phase to `.vigil/artifacts/<TICKET>/`
- NEW `pkg/fix/artifacts_test.go`
- MODIFY `pkg/fix/fix.go` — record artifacts at each phase

**Commit 10: Add watch command and blocked CVE registry**
- NEW `pkg/watch/registry.go` — `Registry` with Load/Save/Add/Remove on `.vigil/blocked.json`
- NEW `pkg/watch/watch.go` — `Run()` loop: poll downstream Go version → re-classify → promote if fixable
- NEW `pkg/watch/registry_test.go`, `pkg/watch/watch_test.go`
- NEW `cmd/watch.go` — flags: `--component`, `--interval 168h`, `--once`, `--fix`

**Commit 11: Record blocked CVEs from assess/scan**
- MODIFY `cmd/assess.go` — if Blocked by Go, add to registry
- MODIFY `cmd/scan.go` — same for batch

### Phase 4: Trivy (commit 12)

**Commit 12: Add Trivy as third detection source**
- NEW `pkg/trivy/trivy.go` — `Run()` executes `trivy fs --format json --scanners vuln`
- NEW `pkg/trivy/parse.go` — parse Trivy JSON schema
- NEW `pkg/trivy/trivy_test.go`
- MODIFY `cmd/scan.go` — run Trivy after govulncheck, cross-reference, add SRC=Trivy column
- MODIFY `Containerfile` — add `trivy` install

### Phase 5: Routing + ARGUS (commits 13–14)

**Commit 13: Add intelligent routing for fix classification**
- NEW `pkg/fix/routing.go` — `DetermineRoute()` returns fix-pipeline vs ai-workflow vs manual
- NEW `pkg/fix/routing_test.go`
- MODIFY `cmd/fix.go` — use routing to decide action

**Commit 14: Add ARGUS ProdSec skills integration**
- NEW `pkg/argus/argus.go` — `FetchSkills()` from GitLab API, `MatchSkill()` by CVE type, local cache
- NEW `pkg/argus/argus_test.go`
- MODIFY `pkg/pr/description.go` — include ARGUS skill guidance in PR body

### Phase 6: Claude Preprocessor + Docs (commits 15–17)

**Commit 15: Add Claude CVE preprocessor**
- NEW `pkg/preprocess/preprocess.go` — `Process()` calls Claude API, caches in `.vigil/cache/cve-preprocessed/`
- NEW `pkg/preprocess/cache.go` — cache load/save
- NEW `pkg/preprocess/preprocess_test.go`
- MODIFY `cmd/assess.go` — add `--preprocess` flag
- Uses raw HTTP (no SDK dependency), requires `ANTHROPIC_API_KEY`

**Commit 16: Update Containerfile, README, and design doc**
- MODIFY `Containerfile` — add `gh` CLI install (Trivy already added in commit 12)
- MODIFY `README.md` — add fix/watch/check-goversion sections, update architecture diagram, update env vars table, update install section
- MODIFY `docs/design-v0.0.2.md` — update non-goals to reflect actual implementation

**Commit 17: Add integration test for fix pipeline**
- NEW `pkg/fix/integration_test.go` — `//go:build integration`, test with temp go.mod + known vuln

## Key Files

| File | Action | Purpose |
|---|---|---|
| `Makefile` | modify | VERSION=0.0.2 |
| `Containerfile` | modify | add trivy + gh CLI |
| `README.md` | modify | full rewrite for v0.0.2 |
| `docs/design-v0.0.2.md` | modify | update non-goals |
| `cmd/fix.go` | new | fix command |
| `cmd/watch.go` | new | watch command |
| `cmd/check_goversion.go` | modify | implement stub |
| `cmd/assess.go` | modify | --fix, --preprocess flags |
| `cmd/scan.go` | modify | --fix, Trivy integration |
| `pkg/fix/*.go` | new | fix pipeline (8 files) |
| `pkg/pr/*.go` | new | PR creation (3 files) |
| `pkg/watch/*.go` | new | watch mode (4 files) |
| `pkg/trivy/*.go` | new | Trivy integration (3 files) |
| `pkg/argus/*.go` | new | ARGUS skills (2 files) |
| `pkg/preprocess/*.go` | new | Claude preprocessor (3 files) |
| `pkg/jira/client.go` | modify | add writeback methods |
| `pkg/jira/transitions.go` | new | transition types |
| `pkg/goversion/check.go` | new | check-goversion impl |

## Deferred to v0.0.3

- **Snyk integration** — per [RHWA-632](https://redhat.atlassian.net/browse/RHWA-632), Snyk upstream is being enabled for medik8s repos. Once available, add Snyk as a fourth detection source alongside Jira + govulncheck + Trivy.
- **ExploitIQ integration** — use [ExploitIQ](https://github.com/RHEcosystemAppEng/vulnerability-analysis) as a deep reachability oracle for ambiguous CVEs. Self-hosted Llama 3.1 70B, matching Claude Sonnet accuracy at ~$1.33/12 CVEs.
- **AI-assisted semantic fixes** — for CVEs requiring code-level refactoring (API migration, deprecated functions, vendor patches), route to an AI workflow that reasons about code semantics. Extends v0.0.2 routing which outputs instructions but doesn't execute AI fixes.
- **Agentic mode** — split Vigil into detection agent and fix agent that can run independently. One Vigil instance continuously scans (detection mode), outputs structured results, and a second Vigil instance picks up Fixable Now results and runs the fix pipeline. This enables parallel, non-blocking operation in CI/CD and supports the agentic SDLC pattern where detection and remediation are decoupled.

## Post-Build Testing

After `make docker-build`, test the latest tag image across 3 components:

```bash
# Test assess mode for each component
podman run --rm -t -e JIRA_API_TOKEN -e GITLAB_PRIVATE_TOKEN \
  quay.io/oraz/vigil:latest scan --component FAR --short

podman run --rm -t -e JIRA_API_TOKEN -e GITLAB_PRIVATE_TOKEN \
  quay.io/oraz/vigil:latest scan --component NHC --short

podman run --rm -t -e JIRA_API_TOKEN -e GITLAB_PRIVATE_TOKEN \
  quay.io/oraz/vigil:latest scan --component NMO --short

# Test fix mode (dry-run)
podman run --rm -t -e JIRA_API_TOKEN -e GITLAB_PRIVATE_TOKEN \
  quay.io/oraz/vigil:latest fix <FIXABLE-TICKET> --dry-run

# Test watch mode (single check)
podman run --rm -t -e JIRA_API_TOKEN -e GITLAB_PRIVATE_TOKEN \
  quay.io/oraz/vigil:latest watch --component FAR --once

# Test check-goversion
podman run --rm -t -e JIRA_API_TOKEN -e GITLAB_PRIVATE_TOKEN \
  quay.io/oraz/vigil:latest check-goversion --operator FAR --want 1.25.9

# Test Trivy source in scan
podman run --rm -t -e JIRA_API_TOKEN -e GITLAB_PRIVATE_TOKEN \
  quay.io/oraz/vigil:latest scan --component FAR --short --discover
```

## Verification

Each commit must pass:
- `go build ./...`
- `go vet ./...`
- `go test ./... -count=1`
- `make lint`

End-to-end after all commits:
- `./bin/vigil fix --help` shows usage
- `./bin/vigil watch --help` shows usage
- `./bin/vigil check-goversion --operator FAR --want 1.25.9` works
- `./bin/vigil scan --component FAR --short` shows Trivy source
- `make docker-build` succeeds with trivy + gh in image
- Image tagged `v0.0.2-X-SHA` on milestone builds
