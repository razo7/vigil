# Vigil v0.0.3-3 -- Build Changelog

**Image:** [`quay.io/oraz/vigil:v0.0.3-3-2fa1d2d`](https://quay.io/repository/oraz/vigil?tab=tags&tag=v0.0.3-3-2fa1d2d)
**Date:** 2026-06-02
**Commits:** 90b56e2..2fa1d2d (10 commits)
**Previous image:** v0.0.3-2

## Highlights

### New

- Add eol_threshold config and --eol-threshold flag
- Add OCP 4.22 and latest operator versions to lifecycle
- Consolidate ACTION column + hardcode downstream Go versions
- Add skopeo cache for downstream Go version in CI
- Add v0.0.4 design tasks for fix-function and skopeo cache
- Add ACTION column design for v0.0.4
- Add BACKPORT column, fix mermaid, and link artifacts
- Add changelog for v0.0.3-2-90b56e2

### Fixes

- Fix GOTOOLCHAIN pinning to always use operator's Go version
- Consolidate ACTION column + hardcode downstream Go versions
- Add v0.0.4 design tasks for fix-function and skopeo cache
- Add ACTION column design for v0.0.4
- Add BACKPORT column, fix mermaid, and link artifacts

### CI / Infrastructure

- Fix GOTOOLCHAIN pinning to always use operator's Go version
- Consolidate ACTION column + hardcode downstream Go versions
- Add skopeo cache for downstream Go version in CI
- Add v0.0.4 design tasks for fix-function and skopeo cache
- Rewrite HTML report with dashboard, mermaid improvements
- Add BACKPORT column, fix mermaid, and link artifacts

## Commits

| SHA | Subject |
|-----|---------|
| [`2fa1d2d`](https://github.com/razo7/vigil/commit/2fa1d2d) | Fix GOTOOLCHAIN pinning to always use operator's Go version |
| [`d8b27eb`](https://github.com/razo7/vigil/commit/d8b27eb) | Add eol_threshold config and --eol-threshold flag |
| [`1cbe656`](https://github.com/razo7/vigil/commit/1cbe656) | Add OCP 4.22 and latest operator versions to lifecycle |
| [`6a895d0`](https://github.com/razo7/vigil/commit/6a895d0) | Consolidate ACTION column + hardcode downstream Go versions |
| [`d9e1560`](https://github.com/razo7/vigil/commit/d9e1560) | Add skopeo cache for downstream Go version in CI |
| [`3767a66`](https://github.com/razo7/vigil/commit/3767a66) | Add v0.0.4 design tasks for fix-function and skopeo cache |
| [`7afefb4`](https://github.com/razo7/vigil/commit/7afefb4) | Add ACTION column design for v0.0.4 |
| [`62193a7`](https://github.com/razo7/vigil/commit/62193a7) | Rewrite HTML report with dashboard, mermaid improvements |
| [`bba864e`](https://github.com/razo7/vigil/commit/bba864e) | Add BACKPORT column, fix mermaid, and link artifacts |
| [`6489e3a`](https://github.com/razo7/vigil/commit/6489e3a) | Add changelog for v0.0.3-2-90b56e2 |

## Files Changed

 22 files changed, 1250 insertions(+), 219 deletions(-)

### By area

- `pkg/downstream/` -- 3 files
- `cmd/` -- 3 files
- `pkg/route/` -- 2 files
- `pkg/config/` -- 2 files
- `pkg/classify/` -- 2 files
- root -- 2 files
- `pkg/types/` -- 1 files
- `pkg/report/` -- 1 files
- `pkg/lifecycle/` -- 1 files
- `pkg/goversion/` -- 1 files
- `pkg/assess/` -- 1 files
- `docs/v0.0.4/` -- 1 files
- `docs/v0.0.3/` -- 1 files
- `.github/workflows/` -- 1 files

