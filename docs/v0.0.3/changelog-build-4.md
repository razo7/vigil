# Vigil v0.0.3-4 -- Build Changelog

**Image:** [`quay.io/oraz/vigil:v0.0.3-4-0bf8273`](https://quay.io/repository/oraz/vigil?tab=tags&tag=v0.0.3-4-0bf8273)
**Date:** 2026-06-03
**Commits:** 2fa1d2d..0bf8273 (10 commits)
**Previous image:** v0.0.3-3

## Highlights

### New

- Add lifecycle-phase qualification to ACTION column
- Update decision tree with ProdsecTeam CVE assessment policies
- Add multi-branch CVE discovery for supported versions
- Add multi-branch discovery and health index to v0.0.4 design
- Add health_index and downstream_go to component config
- Add changelog for v0.0.3-3-2fa1d2d

### Fixes

- Add lifecycle-phase qualification to ACTION column
- Update decision tree with ProdsecTeam CVE assessment policies
- Add multi-branch CVE discovery for supported versions
- Fix mermaid sizing, restore emojis, fix workflow table

### CI / Infrastructure

- Add multi-branch discovery and health index to v0.0.4 design
- Add health_index and downstream_go to component config
- Fix mermaid sizing, restore emojis, fix workflow table

## Commits

| SHA | Subject |
|-----|---------|
| [`0bf8273`](https://github.com/razo7/vigil/commit/0bf8273) | Add lifecycle-phase qualification to ACTION column |
| [`6588d70`](https://github.com/razo7/vigil/commit/6588d70) | Update decision tree with ProdsecTeam CVE assessment policies |
| [`a2128fe`](https://github.com/razo7/vigil/commit/a2128fe) | Track CVEs across all branches instead of deduping |
| [`822aa9c`](https://github.com/razo7/vigil/commit/822aa9c) | Add multi-branch CVE discovery for supported versions |
| [`038883c`](https://github.com/razo7/vigil/commit/038883c) | Add multi-branch discovery and health index to v0.0.4 design |
| [`faa41c8`](https://github.com/razo7/vigil/commit/faa41c8) | Add health_index and downstream_go to component config |
| [`81dfadf`](https://github.com/razo7/vigil/commit/81dfadf) | Fix mermaid sizing, restore emojis, fix workflow table |
| [`5087c54`](https://github.com/razo7/vigil/commit/5087c54) | Show 'No ticket' status for GVC and Trivy discovered CVEs |
| [`87888cc`](https://github.com/razo7/vigil/commit/87888cc) | Download Go toolchain at runtime for pre-1.21 versions |
| [`c09d11f`](https://github.com/razo7/vigil/commit/c09d11f) | Add changelog for v0.0.3-3-2fa1d2d |

## Files Changed

 10 files changed, 408 insertions(+), 94 deletions(-)

### By area

- `cmd/` -- 2 files
- root -- 2 files
- `pkg/lifecycle/` -- 1 files
- `pkg/goversion/` -- 1 files
- `pkg/config/` -- 1 files
- `docs/v0.0.4/` -- 1 files
- `docs/v0.0.3/` -- 1 files
- `.github/workflows/` -- 1 files

