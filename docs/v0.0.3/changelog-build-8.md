# Vigil v0.0.3-8 -- Build Changelog

**Image:** [`quay.io/oraz/vigil:v0.0.3-8-2358d85`](https://quay.io/repository/oraz/vigil?tab=tags&tag=v0.0.3-8-2358d85)
**Date:** 2026-06-05
**Commits:** e3a5408..2358d85 (10 commits)
**Previous image:** v0.0.3-7

## Highlights

### New

- Normalize --go-version, fix display bugs, add tooltips
- Add cross-component CVEs table and version info
- Fix summary parsing and add total row to breakdown table
- Show per-ticket status and Blocked details
- Add changelog for v0.0.3-7-e3a5408

### Fixes

- Cap action width, fix workflow parsing, accept GO_VERSION env
- Only classify as Blocked when Go version is unreleased
- Normalize --go-version, fix display bugs, add tooltips
- Fix summary parsing and add total row to breakdown table
- Explain why Blocked CVEs are blocked
- Count summary by action instead of classification
- Use HOME for .vigil directory instead of working dir

### CI / Infrastructure

- Cap action width, fix workflow parsing, accept GO_VERSION env
- Use HOME for .vigil directory instead of working dir

## Commits

| SHA | Subject |
|-----|---------|
| [`2358d85`](https://github.com/razo7/vigil/commit/2358d85) | Cap action width, fix workflow parsing, accept GO_VERSION env |
| [`da1a0e3`](https://github.com/razo7/vigil/commit/da1a0e3) | Only classify as Blocked when Go version is unreleased |
| [`b018834`](https://github.com/razo7/vigil/commit/b018834) | Normalize --go-version, fix display bugs, add tooltips |
| [`abc47a6`](https://github.com/razo7/vigil/commit/abc47a6) | Add cross-component CVEs table and version info |
| [`97fae65`](https://github.com/razo7/vigil/commit/97fae65) | Fix summary parsing and add total row to breakdown table |
| [`f1972ba`](https://github.com/razo7/vigil/commit/f1972ba) | Explain why Blocked CVEs are blocked |
| [`8b4c7f5`](https://github.com/razo7/vigil/commit/8b4c7f5) | Count summary by action instead of classification |
| [`3c50b91`](https://github.com/razo7/vigil/commit/3c50b91) | Show per-ticket status and Blocked details |
| [`55934fa`](https://github.com/razo7/vigil/commit/55934fa) | Use HOME for .vigil directory instead of working dir |
| [`d427fd4`](https://github.com/razo7/vigil/commit/d427fd4) | Add changelog for v0.0.3-7-e3a5408 |

## Files Changed

 9 files changed, 359 insertions(+), 55 deletions(-)

### By area

- `cmd/` -- 3 files
- `pkg/classify/` -- 2 files
- `pkg/downstream/` -- 1 files
- `pkg/assess/` -- 1 files
- `docs/v0.0.3/` -- 1 files
- `.github/workflows/` -- 1 files

