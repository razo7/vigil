# Vigil v0.0.1-4 -- Build Changelog

**Image:** [`quay.io/oraz/vigil:v0.0.1-4-c28b0da`](https://quay.io/repository/oraz/vigil?tab=tags&tag=v0.0.1-4-c28b0da)
**Date:** 2026-04-27
**Commits:** 742b268..c28b0da (10 commits)
**Previous image:** v0.0.1-3

## Highlights

### New

- Fix component name mappings and jira CLI error handling
- Add source attribution and reachability proof to scan table
- Add ticket status and discovery progress to scan output
- Sort scan table by source, status, priority, reachability
- Generate changelog at milestone image tags
- Add govulncheck as independent CVE discovery source in scan

### Fixes

- Fix component name mappings and jira CLI error handling
- Fix govulncheck path in multi-stage Containerfile
- Reduce post-submit tags to latest and milestone with SHA suffix

### CI / Infrastructure

- Sort scan table by source, status, priority, reachability
- Fix govulncheck path in multi-stage Containerfile
- Use multi-stage build for smaller container image
- Generate changelog at milestone image tags
- Reduce post-submit tags to latest and milestone with SHA suffix

## Commits

| SHA | Subject |
|-----|---------|
| [`c28b0da`](https://github.com/razo7/vigil/commit/c28b0da) | Fix component name mappings and jira CLI error handling |
| [`63f3858`](https://github.com/razo7/vigil/commit/63f3858) | Add source attribution and reachability proof to scan table |
| [`e245a15`](https://github.com/razo7/vigil/commit/e245a15) | Widen STATUS column to fit Closed (Done-Errata) |
| [`f04a14e`](https://github.com/razo7/vigil/commit/f04a14e) | Add ticket status and discovery progress to scan output |
| [`16c1f14`](https://github.com/razo7/vigil/commit/16c1f14) | Sort scan table by source, status, priority, reachability |
| [`8e8b64e`](https://github.com/razo7/vigil/commit/8e8b64e) | Fix govulncheck path in multi-stage Containerfile |
| [`52a7593`](https://github.com/razo7/vigil/commit/52a7593) | Use multi-stage build for smaller container image |
| [`b4c8c2c`](https://github.com/razo7/vigil/commit/b4c8c2c) | Generate changelog at milestone image tags |
| [`b6b02b4`](https://github.com/razo7/vigil/commit/b6b02b4) | Add govulncheck as independent CVE discovery source in scan |
| [`a22d335`](https://github.com/razo7/vigil/commit/a22d335) | Reduce post-submit tags to latest and milestone with SHA suffix |

## Files Changed

 12 files changed, 1161 insertions(+), 120 deletions(-)

### By area

- `pkg/discover/` -- 2 files
- `pkg/assess/` -- 2 files
- root -- 2 files
- `pkg/types/` -- 1 files
- `pkg/jira/` -- 1 files
- `pkg/goversion/` -- 1 files
- `hack/` -- 1 files
- `cmd/` -- 1 files
- `.github/workflows/` -- 1 files

