# Vigil v0.0.2-4 -- Build Changelog

**Image:** [`quay.io/oraz/vigil:v0.0.2-4-6bf534d`](https://quay.io/repository/oraz/vigil?tab=tags&tag=v0.0.2-4-6bf534d)
**Date:** 2026-04-30
**Commits:** ce3b210..6bf534d (10 commits)
**Previous image:** v0.0.2-3

## Highlights

### New

- Push milestone image in same CI run instead of relying on tag trigger
- Add changelog for v0.0.2-3-6f44a1a
- Add Go toolchain to runtime container for govulncheck

### Fixes

- Fix milestone detection to catch up on missed builds
- Update README and fix container Go toolchain stripping
- Show ticket status immediately and fix table column alignment
- Parse version from .z suffix in ticket titles

### CI / Infrastructure

- Push milestone image in same CI run instead of relying on tag trigger
- Fix milestone detection to catch up on missed builds
- Update README and fix container Go toolchain stripping
- Strip Go toolchain in container to reduce image size
- Add Go toolchain to runtime container for govulncheck

## Commits

| SHA | Subject |
|-----|---------|
| [`6bf534d`](https://github.com/razo7/vigil/commit/6bf534d) | Push milestone image in same CI run instead of relying on tag trigger |
| [`532e50e`](https://github.com/razo7/vigil/commit/532e50e) | Add changelog for v0.0.2-3-6f44a1a |
| [`6f44a1a`](https://github.com/razo7/vigil/commit/6f44a1a) | Fix milestone detection to catch up on missed builds |
| [`e719f8e`](https://github.com/razo7/vigil/commit/e719f8e) | Show CVE published date in CREATED column for GVC and Trivy rows |
| [`69ce6a9`](https://github.com/razo7/vigil/commit/69ce6a9) | Update README and fix container Go toolchain stripping |
| [`c059a21`](https://github.com/razo7/vigil/commit/c059a21) | Strip Go toolchain in container to reduce image size |
| [`1735313`](https://github.com/razo7/vigil/commit/1735313) | Add Go toolchain to runtime container for govulncheck |
| [`9dbb108`](https://github.com/razo7/vigil/commit/9dbb108) | Show ticket status immediately and fix table column alignment |
| [`05c84a7`](https://github.com/razo7/vigil/commit/05c84a7) | Surface govulncheck errors and clarify zero-result output |
| [`0e7fb97`](https://github.com/razo7/vigil/commit/0e7fb97) | Parse version from .z suffix in ticket titles |

## Files Changed

 11 files changed, 162 insertions(+), 28 deletions(-)

### By area

- root -- 2 files
- `pkg/types/` -- 1 files
- `pkg/trivy/` -- 1 files
- `pkg/jira/` -- 1 files
- `pkg/goversion/` -- 1 files
- `pkg/discover/` -- 1 files
- `pkg/cve/` -- 1 files
- `docs/v0.0.2/` -- 1 files
- `cmd/` -- 1 files
- `.github/workflows/` -- 1 files

