# Vigil v0.0.2-6 -- Build Changelog

**Image:** [`quay.io/oraz/vigil:v0.0.2-6-6d54abf`](https://quay.io/repository/oraz/vigil?tab=tags&tag=v0.0.2-6-6d54abf)
**Date:** 2026-05-31
**Commits:** 1a22850..6d54abf (10 commits)
**Previous image:** v0.0.2-5

## Highlights

### New

- Add --format html for colored scan reports in browser
- Add --go-version flag to bypass downstream detection
- Use golang:1 in Containerfile to prevent toolchain mismatch
- Promote container as the recommended way to run Vigil
- Make Jira project and URL configurable
- Update README with new flags and ARGUS dual source
- Add changelog for v0.0.2-5-abd3113
- Add --commit flag for point-in-time analysis

### Fixes

- Use fix-function mismatch in classification

### CI / Infrastructure

- Use golang:1 in Containerfile to prevent toolchain mismatch
- Promote container as the recommended way to run Vigil

## Commits

| SHA | Subject |
|-----|---------|
| [`6d54abf`](https://github.com/razo7/vigil/commit/6d54abf) | Add --format html for colored scan reports in browser |
| [`0c41858`](https://github.com/razo7/vigil/commit/0c41858) | Externalize OCP lifecycle data to YAML config |
| [`79fe2da`](https://github.com/razo7/vigil/commit/79fe2da) | Use fix-function mismatch in classification |
| [`a1a527d`](https://github.com/razo7/vigil/commit/a1a527d) | Add --go-version flag to bypass downstream detection |
| [`1820f28`](https://github.com/razo7/vigil/commit/1820f28) | Use golang:1 in Containerfile to prevent toolchain mismatch |
| [`1460113`](https://github.com/razo7/vigil/commit/1460113) | Promote container as the recommended way to run Vigil |
| [`f18fcfe`](https://github.com/razo7/vigil/commit/f18fcfe) | Make Jira project and URL configurable |
| [`7fa7243`](https://github.com/razo7/vigil/commit/7fa7243) | Update README with new flags and ARGUS dual source |
| [`32cc54b`](https://github.com/razo7/vigil/commit/32cc54b) | Add changelog for v0.0.2-5-abd3113 |
| [`abd3113`](https://github.com/razo7/vigil/commit/abd3113) | Add --commit flag for point-in-time analysis |

## Files Changed

 19 files changed, 672 insertions(+), 99 deletions(-)

### By area

- root -- 5 files
- `cmd/` -- 4 files
- `pkg/assess/` -- 3 files
- `pkg/config/` -- 2 files
- `pkg/classify/` -- 2 files
- `pkg/lifecycle/` -- 1 files
- `pkg/discover/` -- 1 files
- `docs/v0.0.2/` -- 1 files

### Removed

- `vigil.yaml.example`

