# Vigil v0.0.3-7 -- Build Changelog

**Image:** [`quay.io/oraz/vigil:v0.0.3-7-e3a5408`](https://quay.io/repository/oraz/vigil?tab=tags&tag=v0.0.3-7-e3a5408)
**Date:** 2026-06-04
**Commits:** a384899..e3a5408 (10 commits)
**Previous image:** v0.0.3-6

## Highlights

### New

- Update consolidated report: totals, executive summary, charts
- Add GitHub advisory API fallback for CVSS scores
- Fix CVSS fetch, action text, SLA, chart colors, workflow
- Group CVEs by ID, fetch CVSS, add SLA, fix charts
- Add changelog for v0.0.3-6-0d3c6a4
- Add git blame commit SHA to call path frames

### Fixes

- Update consolidated report: totals, executive summary, charts
- Show installed version in dependency fix actions
- Show fix details for branch-discovered CVEs
- Fix CVSS fetch, action text, SLA, chart colors, workflow
- Group CVEs by ID, fetch CVSS, add SLA, fix charts
- Reorder columns and polish table output

### CI / Infrastructure

- Show installed version in dependency fix actions
- Add GitHub advisory API fallback for CVSS scores
- Fix CVSS fetch, action text, SLA, chart colors, workflow

## Commits

| SHA | Subject |
|-----|---------|
| [`e3a5408`](https://github.com/razo7/vigil/commit/e3a5408) | Update consolidated report: totals, executive summary, charts |
| [`8d808ba`](https://github.com/razo7/vigil/commit/8d808ba) | Show installed version in dependency fix actions |
| [`f734c96`](https://github.com/razo7/vigil/commit/f734c96) | Show fix details for branch-discovered CVEs |
| [`64866af`](https://github.com/razo7/vigil/commit/64866af) | Add GitHub advisory API fallback for CVSS scores |
| [`27cac43`](https://github.com/razo7/vigil/commit/27cac43) | Sort Jira tickets before discovered CVEs |
| [`1e67740`](https://github.com/razo7/vigil/commit/1e67740) | Fix CVSS fetch, action text, SLA, chart colors, workflow |
| [`e4baa02`](https://github.com/razo7/vigil/commit/e4baa02) | Group CVEs by ID, fetch CVSS, add SLA, fix charts |
| [`7f17cf2`](https://github.com/razo7/vigil/commit/7f17cf2) | Reorder columns and polish table output |
| [`3df741b`](https://github.com/razo7/vigil/commit/3df741b) | Add changelog for v0.0.3-6-0d3c6a4 |
| [`0d3c6a4`](https://github.com/razo7/vigil/commit/0d3c6a4) | Add git blame commit SHA to call path frames |

## Files Changed

 12 files changed, 860 insertions(+), 237 deletions(-)

### By area

- `pkg/assess/` -- 2 files
- `cmd/` -- 2 files
- `pkg/types/` -- 1 files
- `pkg/sla/` -- 1 files
- `pkg/report/` -- 1 files
- `pkg/goversion/` -- 1 files
- `pkg/discover/` -- 1 files
- `pkg/cve/` -- 1 files
- `docs/v0.0.3/` -- 1 files
- `.github/workflows/` -- 1 files

