# Vigil v0.0.2-6 -- Build Changelog

**Image:** [`quay.io/oraz/vigil:v0.0.2-6-c2397b4`](https://quay.io/repository/oraz/vigil?tab=tags&tag=v0.0.2-6-c2397b4)
**Date:** 2026-04-30
**Commits:** bbaae9a..c2397b4 (10 commits)
**Previous image:** v0.0.2-5

## Highlights

### New

- Add Trivy as third vulnerability detection source
- Add Red Hat CA certs to container image
- Implement check-goversion command
- Add v0.0.2 design, implementation plan, and update README
- Add --since flag to filter scan tickets by date
- Rewrite downstream Containerfile resolution

### Fixes

- Add Trivy as third vulnerability detection source
- Add v0.0.2 design, implementation plan, and update README
- Rewrite downstream Containerfile resolution

### CI / Infrastructure

- Add Red Hat CA certs to container image
- Try all name variants for downstream Containerfile

## Commits

| SHA | Subject |
|-----|---------|
| [`c2397b4`](https://github.com/razo7/vigil/commit/c2397b4) | Add Trivy as third vulnerability detection source |
| [`6532a1c`](https://github.com/razo7/vigil/commit/6532a1c) | Add Red Hat CA certs to container image |
| [`de57f59`](https://github.com/razo7/vigil/commit/de57f59) | Implement check-goversion command |
| [`f25c0aa`](https://github.com/razo7/vigil/commit/f25c0aa) | Bump version to 0.0.2 |
| [`23e28bb`](https://github.com/razo7/vigil/commit/23e28bb) | Add v0.0.2 design, implementation plan, and update README |
| [`dbc402f`](https://github.com/razo7/vigil/commit/dbc402f) | Add --since flag to filter scan tickets by date |
| [`641d94c`](https://github.com/razo7/vigil/commit/641d94c) | Rewrite downstream Containerfile resolution |
| [`fb1236f`](https://github.com/razo7/vigil/commit/fb1236f) | Try all name variants for downstream Containerfile |
| [`6507321`](https://github.com/razo7/vigil/commit/6507321) | Remove Containerfile.manager from candidate paths |
| [`0361ebd`](https://github.com/razo7/vigil/commit/0361ebd) | Map NMO to correct GitLab project name |

## Files Changed

 15 files changed, 1568 insertions(+), 78 deletions(-)

### By area

- root -- 4 files
- `pkg/trivy/` -- 2 files
- `pkg/discover/` -- 2 files
- `docs/` -- 2 files
- `cmd/` -- 2 files
- `pkg/goversion/` -- 1 files
- `pkg/downstream/` -- 1 files
- `pkg/assess/` -- 1 files

