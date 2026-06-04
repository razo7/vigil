# Vigil v0.0.3-6 -- Build Changelog

**Image:** [`quay.io/oraz/vigil:v0.0.3-6-0d3c6a4`](https://quay.io/repository/oraz/vigil?tab=tags&tag=v0.0.3-6-0d3c6a4)
**Date:** 2026-06-04
**Commits:** d7cf34d..0d3c6a4 (10 commits)
**Previous image:** v0.0.3-5

## Highlights

### New

- Add git blame commit SHA to call path frames
- Improve scan output: CVE preference, labels, fix types, filename
- Fix action filter and add missing filter options
- Fix multi-branch govulncheck scanning in container mode
- Add changelog for v0.0.3-5-b7ea2b4
- Add CVE assessment skill with severity ratings and timeframes

### Fixes

- Improve scan output: CVE preference, labels, fix types, filename
- Fix action filter and add missing filter options
- Fix HTML filter column indices after layout changes
- Fix multi-branch govulncheck scanning in container mode
- Show Go version transition in fix actions

### CI / Infrastructure

- Fix multi-branch govulncheck scanning in container mode
- Remove redundant scan table from workflow summary

## Commits

| SHA | Subject |
|-----|---------|
| [`0d3c6a4`](https://github.com/razo7/vigil/commit/0d3c6a4) | Add git blame commit SHA to call path frames |
| [`a384899`](https://github.com/razo7/vigil/commit/a384899) | Improve scan output: CVE preference, labels, fix types, filename |
| [`b0d0f34`](https://github.com/razo7/vigil/commit/b0d0f34) | Fix action filter and add missing filter options |
| [`fdad88e`](https://github.com/razo7/vigil/commit/fdad88e) | Fix HTML filter column indices after layout changes |
| [`4aa0c19`](https://github.com/razo7/vigil/commit/4aa0c19) | Fix multi-branch govulncheck scanning in container mode |
| [`a89a5bb`](https://github.com/razo7/vigil/commit/a89a5bb) | Merge Lang into SRC column as SRC (Lang) |
| [`b4a5313`](https://github.com/razo7/vigil/commit/b4a5313) | Remove redundant scan table from workflow summary |
| [`e0d698d`](https://github.com/razo7/vigil/commit/e0d698d) | Show Go version transition in fix actions |
| [`d86dc0b`](https://github.com/razo7/vigil/commit/d86dc0b) | Add changelog for v0.0.3-5-b7ea2b4 |
| [`b7ea2b4`](https://github.com/razo7/vigil/commit/b7ea2b4) | Add CVE assessment skill with severity ratings and timeframes |

## Files Changed

 13 files changed, 544 insertions(+), 79 deletions(-)

### By area

- `pkg/assess/` -- 3 files
- `cmd/` -- 2 files
- `pkg/lifecycle/` -- 1 files
- `pkg/goversion/` -- 1 files
- `pkg/discover/` -- 1 files
- `pkg/config/` -- 1 files
- `docs/v0.0.3/` -- 1 files
- `docs/skills/` -- 1 files
- `.github/workflows/` -- 1 files
- root -- 1 files

