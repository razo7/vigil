# Vigil v0.0.2-7 -- Build Changelog

**Image:** [`quay.io/oraz/vigil:v0.0.2-7-aadbfad`](https://quay.io/repository/oraz/vigil?tab=tags&tag=v0.0.2-7-aadbfad)
**Date:** 2026-04-30
**Commits:** c2397b4..aadbfad (10 commits)
**Previous image:** v0.0.2-6

## Highlights

### New

- Add fix pipeline with 5-strategy cascade and PR creation
- Add Trivy to discover mode and default scan to use Trivy
- Add dependency Go version check via module proxy
- Update README for v0.0.2 features
- Add Claude CVE preprocessor with local caching
- Add ARGUS ProdSec skills integration with GitLab fetch and caching
- Add watch command and blocked CVE registry
- Add Jira writeback methods for transitions, PR links, and labels
- Add changelog for milestone build

### Fixes

- Add fix pipeline with 5-strategy cascade and PR creation
- Fix misassignment to use OCP support phase not RHEL version
- Add dependency Go version check via module proxy
- Add Claude CVE preprocessor with local caching

### CI / Infrastructure

- Add fix pipeline with 5-strategy cascade and PR creation
- Add dependency Go version check via module proxy
- Update README for v0.0.2 features
- Add ARGUS ProdSec skills integration with GitLab fetch and caching
- Add Jira writeback methods for transitions, PR links, and labels
- Add changelog for milestone build

## Commits

| SHA | Subject |
|-----|---------|
| [`aadbfad`](https://github.com/razo7/vigil/commit/aadbfad) | Add fix pipeline with 5-strategy cascade and PR creation |
| [`bf1b959`](https://github.com/razo7/vigil/commit/bf1b959) | Add Trivy to discover mode and default scan to use Trivy |
| [`9677b6b`](https://github.com/razo7/vigil/commit/9677b6b) | Fix misassignment to use OCP support phase not RHEL version |
| [`a4cebb4`](https://github.com/razo7/vigil/commit/a4cebb4) | Add dependency Go version check via module proxy |
| [`2b686a0`](https://github.com/razo7/vigil/commit/2b686a0) | Update README for v0.0.2 features |
| [`b8c125b`](https://github.com/razo7/vigil/commit/b8c125b) | Add Claude CVE preprocessor with local caching |
| [`2c25fa6`](https://github.com/razo7/vigil/commit/2c25fa6) | Add ARGUS ProdSec skills integration with GitLab fetch and caching |
| [`1b060a2`](https://github.com/razo7/vigil/commit/1b060a2) | Add watch command and blocked CVE registry |
| [`5bda654`](https://github.com/razo7/vigil/commit/5bda654) | Add Jira writeback methods for transitions, PR links, and labels |
| [`5814ddc`](https://github.com/razo7/vigil/commit/5814ddc) | Add changelog for milestone build |

## Files Changed

 46 files changed, 3718 insertions(+), 65 deletions(-)

### By area

- `pkg/fix/` -- 13 files
- `cmd/` -- 5 files
- `pkg/goversion/` -- 4 files
- `pkg/watch/` -- 3 files
- `pkg/preprocess/` -- 3 files
- `pkg/pr/` -- 3 files
- `pkg/jira/` -- 3 files
- `pkg/downstream/` -- 3 files
- `pkg/classify/` -- 2 files
- `pkg/argus/` -- 2 files
- `pkg/trivy/` -- 1 files
- `pkg/discover/` -- 1 files
- `pkg/assess/` -- 1 files
- `docs/` -- 1 files
- root -- 1 files

