# Vigil v0.0.2-2 -- Build Changelog

**Image:** [`quay.io/oraz/vigil:v0.0.2-2-3a384a5`](https://quay.io/repository/oraz/vigil?tab=tags&tag=v0.0.2-2-3a384a5)
**Date:** 2026-04-30
**Commits:** aadbfad..3a384a5 (10 commits)
**Previous image:** v0.0.2-1

## Highlights

### New

- Default scan to Vulnerability tickets, add --include-bugs
- Add tag-triggered image push following medik8s pattern
- Add milestone tagging and fix changelog path in CI
- Add repo and image links to README, fix changelog build number
- Reorganize docs and fix per-version build numbering
- Add changelog for milestone build

### Fixes

- Default scan to Vulnerability tickets, add --include-bugs
- Add milestone tagging and fix changelog path in CI
- Add repo and image links to README, fix changelog build number
- Reorganize docs and fix per-version build numbering

### CI / Infrastructure

- Remove stale v0.0.2 changelogs from old numbering
- Trigger CI to rebuild container image
- Add tag-triggered image push following medik8s pattern
- Add milestone tagging and fix changelog path in CI
- Add repo and image links to README, fix changelog build number
- Reorganize docs and fix per-version build numbering
- Add changelog for milestone build

## Commits

| SHA | Subject |
|-----|---------|
| [`3a384a5`](https://github.com/razo7/vigil/commit/3a384a5) | Default scan to Vulnerability tickets, add --include-bugs |
| [`3f23402`](https://github.com/razo7/vigil/commit/3f23402) | Remove redundant --trivy from README examples |
| [`ddea3d0`](https://github.com/razo7/vigil/commit/ddea3d0) | Suppress jira CLI warning when CLI is not installed |
| [`82b6ed0`](https://github.com/razo7/vigil/commit/82b6ed0) | Remove stale v0.0.2 changelogs from old numbering |
| [`a606b6a`](https://github.com/razo7/vigil/commit/a606b6a) | Trigger CI to rebuild container image |
| [`bcb572e`](https://github.com/razo7/vigil/commit/bcb572e) | Add tag-triggered image push following medik8s pattern |
| [`ecfa4a3`](https://github.com/razo7/vigil/commit/ecfa4a3) | Add milestone tagging and fix changelog path in CI |
| [`1d57686`](https://github.com/razo7/vigil/commit/1d57686) | Add repo and image links to README, fix changelog build number |
| [`5320517`](https://github.com/razo7/vigil/commit/5320517) | Reorganize docs and fix per-version build numbering |
| [`86aa031`](https://github.com/razo7/vigil/commit/86aa031) | Add changelog for milestone build |

## Files Changed

 12 files changed, 100 insertions(+), 117 deletions(-)

### By area

- `docs/v0.0.2/` -- 2 files
- `docs/v0.0.1/` -- 2 files
- root -- 2 files
- `pkg/jira/` -- 1 files
- `pkg/discover/` -- 1 files
- `hack/` -- 1 files
- `docs/` -- 1 files
- `cmd/` -- 1 files
- `.github/workflows/` -- 1 files

### Removed

- `docs/changelog-v0.0.2-6.md`

