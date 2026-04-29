# Vigil v0.0.2 — Design

Extends Vigil from a triage-only tool to a triage-and-fix pipeline, informed by the [CVE Assessment Tool Landscape](https://redhat.atlassian.net/browse/RHWA-921?focusedId=16836373&page=com.atlassian.jira.plugin.system.issuetabpanels:comment-tabpanel#comment-16836373) analysis of five tools: [Claude /security-review](https://github.com/anthropics/claude-code-security-review), [ExploitIQ](https://github.com/RHEcosystemAppEng/vulnerability-analysis), [flightctl/ai-workflows](https://github.com/flightctl/ai-workflows/tree/main/cve-fix), and [openshift-assisted/cve-automation](https://github.com/openshift-assisted/cve-automation).

## What v0.0.1 Does

Vigil v0.0.1 is a deterministic Go CLI that triages CVE tickets for medik8s operators. It classifies each CVE into 5 categories (Fixable Now / Blocked by Go / Not Reachable / Not Go / Misassigned), assigns priority, and outputs JSON or Jira comments. It does not generate fixes, write back to Jira, or track blocked CVEs over time.

## What v0.0.2 Adds

| Capability | Source of inspiration |
|---|---|
| Fix PR generation (Go dependency bumps) | openshift-assisted/cve-automation patching strategies |
| Phase-based fix pipeline (patch → validate → PR) | flightctl/ai-workflows 6-phase architecture |
| Jira bidirectional sync (writeback on fix) | openshift-assisted/cve-automation PR monitoring |
| Blocked CVE re-check (`watch` mode) | RHWA-921 requirement: weekly crawler |
| `check-goversion` implementation | v0.0.1 stub, now implemented |

| ARGUS ProdSec skills integration | [ARGUS prodsec-skills](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/tree/main/skills) |
| Claude CVE preprocessor | Offline advisory digestion, cached per CVE |
| Intelligent routing | Route to fix pipeline or AI workflow based on CVE type |

## ARGUS ProdSec Skills

Vigil integrates with the [ARGUS ProdSec skills repository](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/tree/main/skills) to ensure remediation follows Red Hat enterprise security standards. Relevant skills:

| Skill | Link | How Vigil Uses It |
|---|---|---|
| vulnerability-management | [skills/secure_development/supply-chain/vulnerability-management.md](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/blob/main/skills/secure_development/supply-chain/vulnerability-management.md) | CVE response timelines (Critical: 30d, Important: 60d, Moderate: 90d) drive priority calculation |
| go-security | [skills/secure_development/languages/go-security.md](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/blob/main/skills/secure_development/languages/go-security.md) | Go-specific guidance: govulncheck, dependency pinning, go.sum checksums |
| operator-security | [skills/secure_development/kubernetes/operator-security.md](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/blob/main/skills/secure_development/kubernetes/operator-security.md) | K8s operator RBAC, container hardening — validate fix PRs don't weaken security posture |
| differential-review | [skills/security_auditing/audit-workflow/differential-review.md](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/blob/main/skills/security_auditing/audit-workflow/differential-review.md) | Security-focused diff review for generated fix patches |
| sast-finding-triage | [skills/secure_development/rh-secure-sdlc/sast/sast-finding-triage.md](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/blob/main/skills/secure_development/rh-secure-sdlc/sast/sast-finding-triage.md) | SARIF parsing and true/false positive determination during Trivy integration |
| supply-chain-risk-auditor | [skills/secure_development/supply-chain/supply-chain-risk-auditor.md](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/blob/main/skills/secure_development/supply-chain/supply-chain-risk-auditor.md) | Dependency health assessment: maintainer risk, CVE history, abandonment |
| container-hardening | [skills/secure_development/kubernetes/container-hardening.md](https://gitlab.cee.redhat.com/product-security/prodsec-skills/-/blob/main/skills/secure_development/kubernetes/container-hardening.md) | Guidance for Vigil's own Containerfile and operator container images |

## Non-goals (v0.0.2)

- Multi-repo cross-component scan — future
- Non-Go CVE fixes (vendor/patch, workarounds) — always human

---

## Architecture Overview

```
                         ┌──────────────────────────────────────────────────┐
                         │                   VIGIL v0.0.2                  │
                         ├──────────────────────────────────────────────────┤
                         │                                                 │
                         │  ┌─────────┐  ┌─────────┐  ┌─────────────────┐ │
                         │  │ assess  │  │  scan   │  │     watch       │ │
                         │  │ (single)│  │ (batch) │  │ (blocked CVEs)  │ │
                         │  └────┬────┘  └────┬────┘  └───────┬─────────┘ │
                         │       │            │               │           │
                         │       ▼            ▼               ▼           │
                         │  ┌──────────────────────────────────────────┐  │
                         │  │            TRIAGE PIPELINE               │  │
                         │  │  Jira → govulncheck → classify → report │  │
                         │  └──────────────────┬───────────────────────┘  │
                         │                     │                          │
                         │           ┌─────────┴─────────┐               │
                         │           │  Classification?   │               │
                         │           └─────────┬─────────┘               │
                         │                     │                          │
                         │    ┌────────────────┼────────────────┐         │
                         │    ▼                ▼                ▼         │
                         │  Fixable Now    Blocked by Go    Other         │
                         │    │                │            (done)        │
                         │    ▼                ▼                          │
                         │  ┌──────────┐  ┌───────────┐                  │
                         │  │FIX PIPELN│  │  TRACKER  │                  │
                         │  │patch →   │  │  record → │                  │
                         │  │validate →│  │  re-check │                  │
                         │  │PR → jira │  │  weekly   │                  │
                         │  └──────────┘  └───────────┘                  │
                         │                                                │
                         └──────────────────────────────────────────────────┘
```

---

## CLI Commands

### Existing (enhanced)

```
vigil assess <TICKET-ID>      Same as v0.0.1, now with --fix flag
  --fix               After triage, run fix pipeline for Fixable Now CVEs
  --jira              Post assessment + fix status as Jira comment
  (all v0.0.1 flags preserved)

vigil scan --component <NAME>  Same as v0.0.1, now with --fix flag
  --fix               Run fix pipeline for all Fixable Now results
  (all v0.0.1 flags preserved)
```

### New

```
vigil fix <TICKET-ID>          Run fix pipeline only (skip triage, assume Fixable Now)
  --strategy NAME     Force strategy: direct|transitive|replace|major (default: auto)
  --dry-run           Show what would change without modifying files
  --jira              Update Jira ticket on success

vigil watch                    Monitor blocked CVEs, re-check when Go version updates
  --component NAME    Component to watch (default: all)
  --interval DURATION Check interval (default: 168h / 1 week)
  --once              Run one check and exit (for cron)

vigil check-goversion          Check downstream Go version availability
  --operator NAME     Operator name (default: all)
  --want VERSION      Desired Go version (default: from blocked CVEs)
```

---

## DAGs (Directed Acyclic Graphs)

### DAG 1: Assess Mode (single ticket)

The data dependency graph — each node produces data consumed by downstream nodes. Nodes at the same depth can run concurrently.

```
                          ┌──────────────┐
                          │  TICKET ID   │
                          │  (input)     │
                          └──────┬───────┘
                                 │
                                 ▼
                          ┌──────────────┐
                          │ Jira Fetch   │─── ticket metadata, CVE ID,
                          │              │    component, operator version
                          └──────┬───────┘
                                 │
                 ┌───────────────┼───────────────┬────────────────┐
                 ▼               ▼               ▼                ▼
          ┌────────────┐ ┌────────────┐ ┌──────────────┐ ┌─────────────┐
          │ CVE.org    │ │ Resolve    │ │ Downstream   │ │ Lifecycle   │
          │ Fetch      │ │ Repo +     │ │ Go Version   │ │ Lookup      │
          │            │ │ Worktree   │ │ (GitLab +    │ │ (OCP phase) │
          │ CVSS,      │ │            │ │  Skopeo)     │ │             │
          │ severity,  │ │            │ │              │ │             │
          │ CWE        │ │            │ │              │ │             │
          └─────┬──────┘ └──────┬─────┘ └──────┬───────┘ └──────┬──────┘
                │               │              │                │
                │               ▼              │                │
                │        ┌────────────┐        │                │
                │        │ go.mod     │        │                │
                │        │ Parse      │        │                │
                │        └──────┬─────┘        │                │
                │               │              │                │
                │               ▼              │                │
                │        ┌────────────┐        │                │
                │        │ govulncheck│        │                │
                │        │ Run + Parse│        │                │
                │        └──────┬─────┘        │                │
                │               │              │                │
                │               ▼              │                │
                │        ┌────────────┐        │                │
                │        │ Gerrit CL  │        │                │
                │        │ Fix Funcs  │        │                │
                │        └──────┬─────┘        │                │
                │               │              │                │
                └───────────────┼──────────────┘                │
                                │                               │
                                ▼                               │
                         ┌─────────────┐                        │
                         │  Classify   │◄───────────────────────┘
                         │  + Priority │
                         └──────┬──────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
             ┌────────────┐         ┌────────────┐
             │  Report    │         │ Jira       │
             │  (stdout)  │         │ Comment    │
             └────────────┘         └────────────┘
```

### DAG 2: Fix Mode (single ticket)

The fix pipeline — triggered after triage produces a "Fixable Now" classification, or directly via `vigil fix`.

```
                    ┌─────────────────┐
                    │  Triage Result  │
                    │  (Fixable Now)  │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Strategy Select │─── pick lowest-risk strategy
                    │ (orchestrator)  │    that resolves the CVE
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
       ┌────────────┐ ┌────────────┐ ┌──────────────┐
       │  Direct    │ │ Transitive │ │   Replace    │
       │  Update    │ │ Update     │ │  Directive   │
       │            │ │            │ │              │
       │ go get     │ │ find parent│ │ go mod edit  │
       │ pkg@ver    │ │ bump parent│ │ -replace     │
       └──────┬─────┘ └──────┬─────┘ └──────┬───────┘
              │              │              │
              └──────────────┼──────────────┘
                             │ (first success wins)
                             ▼
                    ┌─────────────────┐
                    │   go mod tidy   │
                    └────────┬────────┘
                             │
                    ┌────────┴────────┐
                    ▼                 ▼
             ┌────────────┐   ┌────────────┐
             │ govulncheck│   │  go build  │
             │ Re-verify  │   │  (compile  │
             │ CVE gone?  │   │   check)   │
             └──────┬─────┘   └──────┬─────┘
                    │                │
                    └────────┬───────┘
                             │
                             ▼
                     ┌───────────────┐
                     │ Tests Pass?   │
                     │ go test ./... │
                     └───────┬───────┘
                             │
                  ┌──────────┴──────────┐
                  ▼                     ▼
           ┌────────────┐        ┌────────────┐
           │ Create     │        │ Jira       │
           │ Draft PR   │        │ Writeback  │
           │ (gh pr     │        │ (link PR,  │
           │  create    │        │  status)   │
           │  --draft)  │        │            │
           └────────────┘        └────────────┘
```

### DAG 3: Scan Mode (batch)

Batch processing — the outer loop parallelizes ticket assessment.

```
             ┌──────────────┐
             │  Component   │
             │  (input)     │
             └──────┬───────┘
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
   ┌────────────┐      ┌────────────┐
   │ Jira Search│      │ govulncheck│
   │ (tickets)  │      │ Discovery  │
   └──────┬─────┘      └──────┬─────┘
          │                   │
          ▼                   │
   ┌────────────┐             │
   │ For each   │             │
   │ ticket:    │             │
   │ ┌────────┐ │             │
   │ │Assess  │ │             │
   │ │Pipeline│ │             │
   │ └───┬────┘ │             │
   │     │      │             │
   │     ▼      │             │
   │ ┌────────┐ │             │
   │ │Fixable?│ │             │
   │ │--fix?  │ │             │
   │ └───┬────┘ │             │
   │     │yes   │             │
   │     ▼      │             │
   │ ┌────────┐ │             │
   │ │Fix     │ │             │
   │ │Pipeline│ │             │
   │ └────────┘ │             │
   └──────┬─────┘             │
          │                   │
          └─────────┬─────────┘
                    │
                    ▼
             ┌────────────┐
             │ Cross-match│─── discovered CVEs vs tickets
             │ Gap Report │    (CVEs with no ticket)
             └──────┬─────┘
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
   ┌────────────┐      ┌────────────┐
   │ Table /    │      │ Summary    │
   │ JSON       │      │ File       │
   │ Output     │      │            │
   └────────────┘      └────────────┘
```

### DAG 4: Watch Mode (blocked CVE tracker)

Periodic re-evaluation of blocked CVEs when downstream Go version changes.

```
             ┌──────────────┐
             │  Interval    │
             │  Trigger     │
             │  (cron/loop) │
             └──────┬───────┘
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
   ┌────────────────┐  ┌────────────────┐
   │ Load Blocked   │  │ Check          │
   │ CVE Registry   │  │ Downstream     │
   │ (local JSON)   │  │ Go Version     │
   └──────┬─────────┘  └──────┬─────────┘
          │                   │
          └─────────┬─────────┘
                    │
                    ▼
             ┌────────────┐
             │ Go Version │
             │ Changed?   │
             └──────┬─────┘
                    │
            ┌───────┴───────┐
            │no             │yes
            ▼               ▼
     ┌────────────┐  ┌─────────────┐
     │ Log: no    │  │ Re-classify │
     │ change     │  │ each blocked│
     │ Sleep      │  │ CVE         │
     └────────────┘  └──────┬──────┘
                            │
                     ┌──────┴──────┐
                     ▼             ▼
              ┌───────────┐ ┌───────────┐
              │ Now       │ │ Still     │
              │ Fixable → │ │ Blocked → │
              │ Fix Pipeln│ │ Update    │
              │ (or alert)│ │ registry  │
              └───────────┘ └───────────┘
```

---

## FSMs (Finite State Machines)

### FSM 1: Ticket Lifecycle (overall)

The states a CVE ticket passes through in Vigil, from discovery to resolution.

```
                              ┌─────────┐
                              │UNKNOWN  │
                              │         │
                              └────┬────┘
                                   │ discover / assess
                                   ▼
                              ┌─────────┐
                        ┌─────│TRIAGING │─────┐
                        │     │         │     │
                        │     └────┬────┘     │
                        │          │          │
               ┌────────┴──┐      │     ┌────┴────────┐
               │MISASSIGNED │      │     │ NOT GO      │
               │            │      │     │             │
               │(terminal)  │      │     │(terminal)   │
               └────────────┘      │     └─────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
             ┌───────────┐ ┌────────────┐ ┌────────────┐
             │NOT        │ │BLOCKED     │ │FIXABLE     │
             │REACHABLE  │ │            │ │            │
             │           │ │            │ │            │
             │(terminal) │ │            │ │            │
             └───────────┘ └─────┬──────┘ └──────┬─────┘
                                 │               │
                           Go version            │ --fix
                           updated               │
                                 │               │
                                 ▼               ▼
                          ┌────────────┐  ┌────────────┐
                          │RE-TRIAGING │  │PATCHING    │
                          │            │  │            │
                          └──────┬─────┘  └──────┬─────┘
                                 │               │
                          ┌──────┴──────┐        │
                          ▼             ▼        │
                   ┌───────────┐ ┌──────────┐    │
                   │STILL      │ │NOW       │    │
                   │BLOCKED    │ │FIXABLE ──┼────┘
                   │(back to   │ │          │
                   │ BLOCKED)  │ └──────────┘
                   └───────────┘
                                         │
                                         ▼
                                  ┌────────────┐
                                  │VALIDATING  │
                                  │            │
                                  └──────┬─────┘
                                         │
                                  ┌──────┴──────┐
                                  ▼             ▼
                           ┌───────────┐ ┌───────────┐
                           │FIX FAILED │ │PR CREATED │
                           │           │ │           │
                           │(back to   │ └─────┬─────┘
                           │ FIXABLE,  │       │
                           │ try next  │       ▼
                           │ strategy) │ ┌───────────┐
                           └───────────┘ │JIRA       │
                                         │UPDATED    │
                                         │           │
                                         │(terminal) │
                                         └───────────┘
```

### FSM 2: Fix Pipeline Strategy Cascade

The strategy orchestrator tries strategies in ascending risk order. Each strategy is a self-contained attempt.

```
     ┌──────────┐
     │  ENTRY   │
     │(Fixable  │
     │ Now CVE) │
     └────┬─────┘
          │
          ▼
     ┌──────────┐    success    ┌───────────┐
     │ DIRECT   │──────────────►│ VALIDATE  │
     │ UPDATE   │               │           │
     │          │               └─────┬─────┘
     │ go get   │                     │
     │ pkg@fix  │              ┌──────┴──────┐
     └────┬─────┘              ▼             ▼
          │ fail        ┌───────────┐ ┌───────────┐
          ▼             │ PASS →    │ │ FAIL →    │
     ┌──────────┐       │ PR CREATE│ │ ROLLBACK  │
     │TRANSITIVE│       └──────────┘ └─────┬─────┘
     │ UPDATE   │                          │
     │          │    success               │ retry with
     │ bump     │───────────►VALIDATE      │ next strategy
     │ parent   │                          │
     └────┬─────┘                          │
          │ fail                           │
          ▼                                │
     ┌──────────┐                          │
     │ REPLACE  │    success               │
     │DIRECTIVE │───────────►VALIDATE      │
     │          │                          │
     │ go mod   │                          │
     │ -replace │                          │
     └────┬─────┘                          │
          │ fail                           │
          ▼                                │
     ┌──────────┐                          │
     │ MAJOR    │    success               │
     │ BUMP     │───────────►VALIDATE ─────┘
     │          │
     │ (needs   │
     │  human   │
     │  OK)     │
     └────┬─────┘
          │ fail (all strategies exhausted)
          ▼
     ┌──────────┐
     │ MANUAL   │
     │ REQUIRED │
     │          │
     │ report + │
     │ escalate │
     └──────────┘
```

### FSM 3: Watch Mode (blocked CVE monitor)

```
     ┌──────────┐
     │  IDLE    │◄──────────────────────────────┐
     │          │                               │
     └────┬─────┘                               │
          │ interval elapsed                    │
          ▼                                     │
     ┌──────────┐                               │
     │CHECKING  │                               │
     │GO VERSION│                               │
     └────┬─────┘                               │
          │                                     │
     ┌────┴─────┐                               │
     ▼          ▼                               │
  no change   new version                       │
     │          │                               │
     │          ▼                               │
     │    ┌──────────┐                          │
     │    │EVALUATING│                          │
     │    │BLOCKED   │                          │
     │    │CVEs      │                          │
     │    └────┬─────┘                          │
     │         │                                │
     │    ┌────┴─────────────┐                  │
     │    ▼                  ▼                  │
     │  still blocked     now fixable           │
     │    │                  │                   │
     │    │                  ▼                   │
     │    │           ┌──────────┐              │
     │    │           │PROMOTING │              │
     │    │           │TO FIXABLE│              │
     │    │           │          │              │
     │    │           │reclassify│              │
     │    │           │+ notify  │              │
     │    │           └────┬─────┘              │
     │    │                │                    │
     │    │           ┌────┴─────┐              │
     │    │           ▼          ▼              │
     │    │        --fix?     report only       │
     │    │           │          │              │
     │    │           ▼          │              │
     │    │     ┌──────────┐    │              │
     │    │     │FIX       │    │              │
     │    │     │PIPELINE  │    │              │
     │    │     └────┬─────┘    │              │
     │    │          │          │              │
     └────┴──────────┴──────────┴──────────────┘
                   (back to IDLE)
```

### FSM 4: Jira Sync States

How Vigil manages Jira ticket state transitions.

```
     ┌───────────────┐
     │ TICKET OPEN   │
     │ (New/To Do)   │
     └───────┬───────┘
             │ vigil assess/scan
             ▼
     ┌───────────────┐
     │ ASSESSED      │─── Vigil comment posted
     │               │    with classification
     └───────┬───────┘
             │
        ┌────┴────────────────┐
        ▼                     ▼
  ┌───────────┐        ┌───────────┐
  │ NO ACTION │        │ FIX IN    │
  │ NEEDED    │        │ PROGRESS  │
  │           │        │           │─── Vigil comment:
  │ Not       │        │ Draft PR  │    "fix attempted,
  │ Reachable,│        │ created   │     PR: <link>"
  │ Misassign,│        └─────┬─────┘
  │ Not Go    │              │
  └───────────┘              │ PR merged (external)
                             ▼
                      ┌───────────┐
                      │ MODIFIED  │─── Vigil updates ticket
                      │           │    status + links PR
                      └───────────┘
```

---

## Package Layout (new/changed packages)

```
vigil/
  cmd/
    fix.go             NEW — Fix pipeline command
    watch.go           NEW — Blocked CVE monitor command
    check_goversion.go IMPL — Was stub, now implemented
  pkg/
    fix/               NEW — Fix pipeline orchestration
      fix.go           Strategy orchestrator (cascade logic)
      strategy.go      Strategy interface
      direct.go        Direct dependency update
      transitive.go    Transitive dependency update
      replace.go       Go replace directive strategy
      validate.go      Post-fix validation (govulncheck re-run, build, test)
    pr/                NEW — Pull request creation
      pr.go            Draft PR via gh CLI
    watch/             NEW — Blocked CVE monitor
      watch.go         Interval loop, Go version polling
      registry.go      Local JSON registry of blocked CVEs
    jira/
      client.go        ENHANCED — add writeback: comment, status transition, link PR
    assess/
      assess.go        ENHANCED — return Result for fix pipeline consumption
    (all other packages unchanged)
```

## Fix Strategies (from openshift-assisted/cve-automation)

| # | Strategy | Risk | Command | When |
|---|---|---|---|---|
| 1 | Direct Update | Low | `go get <pkg>@<fix-version>` | Vulnerable package is a direct dependency |
| 2 | Transitive Update | Medium | `go get <parent>@latest` | Vulnerable package pulled in transitively; bump the introducer |
| 3 | Replace Directive | Medium | `go mod edit -replace <old>=<new>` | Direct update not available or breaks API compat |
| 4 | Major Bump | High | `go get <pkg>@<major>` + code changes | Fix only in next major version (needs human approval) |

Strategy 4 requires `--approve-major` flag or interactive confirmation.

## Blocked CVE Registry

Local JSON file (`.vigil/blocked.json`) tracking CVEs classified as Blocked by Go:

```json
{
  "blocked": [
    {
      "ticket": "RHWA-811",
      "cve": "CVE-2026-27137",
      "component": "FAR",
      "needed_go": "1.26.1",
      "current_downstream_go": "1.20.12",
      "first_seen": "2026-04-28",
      "last_checked": "2026-04-28",
      "cvss": 7.5,
      "priority": "Low",
      "reachability": "TEST-ONLY"
    }
  ]
}
```

`vigil watch` reads this file, polls downstream Go version, and re-classifies when unblocked.

## Validation Checklist (post-fix)

1. `go mod tidy` — clean up go.sum
2. `govulncheck -json ./...` — confirm CVE no longer reported
3. `go build ./...` — compile check
4. `go test ./...` — test suite (with timeout)
5. If any fail → rollback `go.mod` + `go.sum`, try next strategy

## Environment Variables (new)

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `GITHUB_TOKEN` | for fix | — | Draft PR creation via `gh` CLI |
| `VIGIL_REGISTRY` | no | `.vigil/blocked.json` | Blocked CVE registry path |

All v0.0.1 env vars unchanged.

## Known Limitations (v0.0.2)

1. **Fix strategies are Go-only** — no support for other ecosystems (aligns with medik8s scope)
2. **Single-repo fix** — each `vigil fix` operates on one repo; no cross-repo coordinated fixes
3. **Major bump needs human** — strategy 4 always requires explicit approval
4. **Watch mode is local** — blocked CVE registry is a local file, not shared. Future: Jira label or custom field

## v0.0.3 Roadmap

### Snyk Integration

Per [RHWA-632](https://redhat.atlassian.net/browse/RHWA-632), Snyk upstream is being enabled for medik8s repos. Add Snyk as a fourth detection source alongside Jira + govulncheck + Trivy.

### ExploitIQ Integration

Use [ExploitIQ](https://github.com/RHEcosystemAppEng/vulnerability-analysis) ([presentation](https://docs.google.com/presentation/d/18JpD2TM1bXGm1WJZ1PsrsxhGpITdLUfGV4oQa15Y7FI/edit), [cost analysis](https://docs.google.com/document/d/1IB_M8PoQPTXGlpsLwRE9-98B9TUmahIAfFzmMjxVReE/edit)) as a deep reachability oracle for ambiguous CVEs that govulncheck can't resolve deterministically. Self-hosted Llama 3.1 70B, matching Claude Sonnet accuracy at ~$1.33/12 CVEs.

### AI-Assisted Semantic Fixes

For CVEs that require code-level refactoring (not just dependency bumps) — API migration, deprecated function replacement, vendor patches — route to an AI workflow (flightctl cve-fix pattern) that can reason about code semantics. This extends the intelligent routing from v0.0.2 which currently outputs instructions but does not execute AI-assisted fixes.

### Agentic Mode

Split Vigil into two independently runnable agents:

```
┌─────────────────────┐         ┌─────────────────────┐
│  Detection Agent    │         │  Fix Agent           │
│                     │  JSON   │                      │
│  vigil scan         │────────►│  vigil fix --batch   │
│    --detect-only    │ results │    --from-stdin      │
│    --output json    │         │                      │
│                     │         │                      │
│  Runs continuously  │         │  Picks up Fixable    │
│  (cron / watch)     │         │  Now results, runs   │
│                     │         │  fix pipeline        │
└─────────────────────┘         └─────────────────────┘
```

Enables parallel, non-blocking operation in CI/CD. The detection agent continuously scans and outputs structured results; the fix agent consumes them and creates PRs. Supports the agentic SDLC pattern where detection and remediation are decoupled.
