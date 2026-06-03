# Vigil v0.0.3-5 -- Build Changelog

**Image:** [`quay.io/oraz/vigil:v0.0.3-5-b7ea2b4`](https://quay.io/repository/oraz/vigil?tab=tags&tag=v0.0.3-5-b7ea2b4)
**Date:** 2026-06-03
**Commits:** 391b8bd..b7ea2b4 (10 commits)
**Previous image:** v0.0.3-4

## Highlights

### New

- Add CVE assessment skill with severity ratings and timeframes
- Add line numbers and repo links to mermaid call paths
- Improve scan table layout and content
- Add SLA tracking with dependent due date calculation
- Add executive summary to consolidated report
- Add version to discovered CVEs and Trivy multi-branch scan
- Add persistent report hosting to v0.0.4 design

### Fixes

- Improve scan table layout and content
- Fix rhwa_to_ocp mapping with verified values
- Fix mermaid links, sizing, PACKAGE-LEVEL, and consolidated HTML

## Commits

| SHA | Subject |
|-----|---------|
| [`b7ea2b4`](https://github.com/razo7/vigil/commit/b7ea2b4) | Add CVE assessment skill with severity ratings and timeframes |
| [`d7cf34d`](https://github.com/razo7/vigil/commit/d7cf34d) | Add line numbers and repo links to mermaid call paths |
| [`9a05f06`](https://github.com/razo7/vigil/commit/9a05f06) | Improve scan table layout and content |
| [`869af93`](https://github.com/razo7/vigil/commit/869af93) | Add SLA tracking with dependent due date calculation |
| [`49d935d`](https://github.com/razo7/vigil/commit/49d935d) | Fix rhwa_to_ocp mapping with verified values |
| [`33c43a8`](https://github.com/razo7/vigil/commit/33c43a8) | Add executive summary to consolidated report |
| [`1698f9c`](https://github.com/razo7/vigil/commit/1698f9c) | Add version to discovered CVEs and Trivy multi-branch scan |
| [`49fa40c`](https://github.com/razo7/vigil/commit/49fa40c) | Add persistent report hosting to v0.0.4 design |
| [`df56ecf`](https://github.com/razo7/vigil/commit/df56ecf) | Consolidate artifacts into single vigil-report download |
| [`2d7069b`](https://github.com/razo7/vigil/commit/2d7069b) | Fix mermaid links, sizing, PACKAGE-LEVEL, and consolidated HTML |

## Files Changed

 16 files changed, 936 insertions(+), 130 deletions(-)

### By area

- `pkg/goversion/` -- 3 files
- `pkg/types/` -- 2 files
- `pkg/sla/` -- 2 files
- `cmd/` -- 2 files
- `pkg/report/` -- 1 files
- `pkg/lifecycle/` -- 1 files
- `pkg/assess/` -- 1 files
- `docs/v0.0.4/` -- 1 files
- `docs/skills/` -- 1 files
- `.github/workflows/` -- 1 files
- root -- 1 files

