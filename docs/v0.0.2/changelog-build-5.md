# Vigil v0.0.2-5 -- Build Changelog

**Image:** [`quay.io/oraz/vigil:v0.0.2-5-abd3113`](https://quay.io/repository/oraz/vigil?tab=tags&tag=v0.0.2-5-abd3113)
**Date:** 2026-05-28
**Commits:** d548960..abd3113 (10 commits)
**Previous image:** v0.0.2-4

## Highlights

### New

- Add --commit flag for point-in-time analysis
- Add public GitHub as primary ARGUS skills source
- Externalize component config to optional YAML file
- Add UPDATED column to scan --short table
- Pin govulncheck to go.mod Go version for consistent stdlib results

### Fixes

- Fix milestone image push to use same container tool as build

### CI / Infrastructure

- Pin govulncheck to go.mod Go version for consistent stdlib results
- Fix milestone image push to use same container tool as build

## Commits

| SHA | Subject |
|-----|---------|
| [`abd3113`](https://github.com/razo7/vigil/commit/abd3113) | Add --commit flag for point-in-time analysis |
| [`1a22850`](https://github.com/razo7/vigil/commit/1a22850) | Add public GitHub as primary ARGUS skills source |
| [`376ce52`](https://github.com/razo7/vigil/commit/376ce52) | Externalize component config to optional YAML file |
| [`bc8d823`](https://github.com/razo7/vigil/commit/bc8d823) | Add UPDATED column to scan --short table |
| [`5004289`](https://github.com/razo7/vigil/commit/5004289) | Use GOTOOLCHAIN=local for mismatched Go minor versions |
| [`79f85a5`](https://github.com/razo7/vigil/commit/79f85a5) | Retry git clone with HTTP/1.1 on HTTP/2 stream errors |
| [`aea6244`](https://github.com/razo7/vigil/commit/aea6244) | Use dynamic column widths in scan table output |
| [`d57cc9e`](https://github.com/razo7/vigil/commit/d57cc9e) | Always pin GOTOOLCHAIN to go.mod version for govulncheck |
| [`920ff77`](https://github.com/razo7/vigil/commit/920ff77) | Pin govulncheck to go.mod Go version for consistent stdlib results |
| [`a8aee0d`](https://github.com/razo7/vigil/commit/a8aee0d) | Fix milestone image push to use same container tool as build |

## Files Changed

 21 files changed, 712 insertions(+), 147 deletions(-)

### By area

- `cmd/` -- 5 files
- `pkg/assess/` -- 3 files
- root -- 3 files
- `pkg/config/` -- 2 files
- `pkg/argus/` -- 2 files
- `pkg/types/` -- 1 files
- `pkg/jira/` -- 1 files
- `pkg/goversion/` -- 1 files
- `pkg/fix/` -- 1 files
- `pkg/discover/` -- 1 files
- `.github/workflows/` -- 1 files

