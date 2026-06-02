# ACTION Column Design (v0.0.4)

Consolidates CLASSIFICATION + BACKPORT into a single actionable directive per CVE ticket.

## Decision Tree

```
1. Is it a Go CVE?
   ├─ No → ❓ Unknown (manual review)
   └─ Yes ↓

2. Is the image a bundle?
   ├─ Yes + CVE targets Go code → ↩️ Misassigned (bundle has no Go runtime)
   ├─ Yes + CVE targets non-Go → ❓ Unknown (check if bundle uses it)
   └─ No ↓

3. Is the operator version EOL?
   ├─ Yes → ↩️ EOL (no action)
   └─ No ↓

4. Is the code reachable? (govulncheck + fix-function match)
   ├─ Not imported → 🟢 No action (not imported)
   ├─ Module-level only → 🟢 No action (go.mod only)
   ├─ Fix-function mismatch → 🟢 No action (fixed functions not called)
   │   └─ Only for Go stdlib CVEs with Gerrit CLs
   │      Third-party deps: falls back to govulncheck only
   └─ Reachable or Package-level ↓

5. Is the fix deployable? (Go version check via skopeo)
   ├─ Fix needs newer Go than downstream → 🟠⏳ Blocked (needs Go X.Y.Z)
   │   └─ Downstream Go version from:
   │      1. Cached skopeo result (from last VPN run)
   │      2. --go-version flag (explicit override)
   │      3. Live skopeo query (requires VPN)
   └─ Fix is deployable ↓

6. Which supported versions are affected?
   ├─ Check ALL supported versions (not just latest)
   ├─ List each affected version
   └─ 🔴🔧 Fix on v0.2, v0.4, v0.6
```

## ACTION Column Values

| Value | Meaning | Input signals |
|-------|---------|---------------|
| 🔴🔧 Fix on v0.2, v0.4 | Specific versions needing fix | Reachability + version scan |
| 🟠⏳ Blocked (Go 1.26+) | Can't deploy fix yet | Downstream Go version check |
| 🟢 No action | Not reachable / not imported | govulncheck reachability |
| 🟢 No action (verified) | Fix functions not called | govulncheck + Gerrit CL |
| ❓ Manual review | Non-Go or ambiguous | Language detection |
| ↩️ EOL | Unsupported version | OCP lifecycle |
| ↩️ Misassigned | Go CVE on bundle image | Image type detection |

## Reachability Confidence

| Confidence | Method | When |
|------------|--------|------|
| High | govulncheck + Gerrit fix-function match | Go stdlib CVEs with Gerrit CLs |
| Medium | govulncheck only (REACHABLE/PACKAGE-LEVEL) | All Go CVEs |
| Low | No govulncheck (e.g., non-Go, bundle) | Non-Go CVEs |

## Downstream Go Version Sources (priority order)

1. **Cached skopeo result** — file `.vigil/downstream-go-cache.json` from last VPN-connected run
2. **`--go-version` flag** — explicit CLI override
3. **Live skopeo query** — requires VPN access to gitlab.cee.redhat.com
4. **Fallback** — use go.mod version with warning: "downstream Go version unknown, using go.mod"
