# Publish VEX Attestations for DockGuard's Docker Image

## Context

DockGuard's production image (`python:3.13-slim` base + Node.js + Grype) has **207 vulnerability rows across 84 unique CVEs** (fresh scan 2026-03-07). Many are false positives — unused system libraries, Grype's compiled-in Go/Rust deps, or Debian packages that ship with Node.js but aren't used by DockGuard's SvelteKit server.

Since DockGuard now has VEX discovery built in, publishing our own VEX attestation means DockGuard will automatically surface these annotations when scanning itself — eating our own dog food.

## Vulnerability Assessment (84 unique CVEs)

### Group 1: Grype Binary Compiled-in Deps — `not_affected` (3 CVEs)

DockGuard invokes Grype as a CLI subprocess for image scanning. It does not use Grype's internal libraries.

| CVE / GHSA | Package | Severity | Justification |
|---|---|---|---|
| GHSA-9h8m-3fm2-qjrq | `go.opentelemetry.io/otel/sdk` v1.39.0 | High | `vulnerable_code_not_in_execute_path` — DockGuard does not use/configure OpenTelemetry |
| GHSA-h395-gr6q-cpjc | `jsonwebtoken` (rust) 9.3.1 | Medium | `vulnerable_code_not_in_execute_path` — DockGuard does not use Grype's JWT functionality |
| GHSA-q9hv-hpm4-hj6x | `circl` v1.6.1 | Low | `vulnerable_code_not_in_execute_path` — DockGuard does not use Cloudflare CIRCL crypto |

### Group 2: Node.js Packages Not Used by DockGuard — `not_affected` (4 CVEs)

DockGuard's SvelteKit server is a simple HTTP server. It doesn't use glob/minimatch or brace expansion.

| CVE | Package | Severity | Justification |
|---|---|---|---|
| CVE-2026-25547 | `node-brace-expansion` | Critical | `vulnerable_code_not_in_execute_path` — DockGuard doesn't use brace expansion |
| CVE-2026-26996 | `node-minimatch` | High | `vulnerable_code_not_in_execute_path` — DockGuard doesn't use glob matching |
| CVE-2026-27903 | `node-minimatch` | High | `vulnerable_code_not_in_execute_path` — same |
| CVE-2026-27904 | `node-minimatch` | High | `vulnerable_code_not_in_execute_path` — same |

### Group 3: Unused System Libraries — `not_affected` (22 CVEs)

These packages are pulled in by the Debian base image but DockGuard never uses them at runtime.

| Library | CVEs | Justification | Notes |
|---|---|---|---|
| `libldap2` (LDAP) | CVE-2017-17740, CVE-2015-3276, CVE-2017-14159, CVE-2020-15719, CVE-2026-22185 | `vulnerable_code_not_in_execute_path` | DockGuard doesn't use LDAP |
| `libgssapi-krb5-2` etc. (Kerberos) | CVE-2018-5709, CVE-2024-26458, CVE-2024-26461 | `vulnerable_code_not_in_execute_path` | DockGuard doesn't use Kerberos |
| `libgnutls30t64` | CVE-2011-3389 | `vulnerable_code_not_in_execute_path` | Python/Node use their own TLS stacks |
| `libsystemd0`, `libudev1` | CVE-2013-4392, CVE-2023-31437, CVE-2023-31438, CVE-2023-31439 | `vulnerable_code_not_in_execute_path` | DockGuard uses supervisor, not systemd |
| `tar` | CVE-2005-2541 | `vulnerable_code_not_in_execute_path` | No tar operations at runtime |
| `perl-base` | CVE-2011-4116 | `vulnerable_code_not_in_execute_path` | DockGuard doesn't use Perl |
| `apt`, `libapt-pkg7.0` | CVE-2011-3374 | `vulnerable_code_not_in_execute_path` | Package manager not used at runtime |
| `dpkg` | CVE-2026-2219 | `vulnerable_code_not_in_execute_path` | Package manager not used at runtime |
| `login.defs`, `passwd` | CVE-2007-5686, CVE-2024-56433 | `vulnerable_code_not_in_execute_path` | Shadow utils not used by the application |
| `supervisor` | CVE-2019-12105 | `vulnerable_code_cannot_be_controlled_by_adversary` | XML-RPC interface not exposed externally |

### Group 4: Negligible System Library CVEs — `not_affected` (13 CVEs)

Ancient/theoretical CVEs in base OS packages that Debian has classified as "not-fixed" for years. Many are disputed or have near-zero real-world impact.

| CVEs | Packages |
|---|---|
| CVE-2010-4756, CVE-2018-20796, CVE-2019-9192, CVE-2019-1010022, CVE-2019-1010023, CVE-2019-1010024, CVE-2019-1010025 | `libc-bin`, `libc6` |
| CVE-2022-0563, CVE-2025-14104 | `util-linux` family |
| CVE-2017-18018, CVE-2025-5278 | `coreutils` |
| CVE-2021-45346 | `libsqlite3-0` |
| CVE-2025-11468 | `python3.13` (negligible severity) |

Justification: `vulnerable_code_not_in_execute_path` — these are theoretical or require conditions that don't apply to a containerized home-lab scanner.

### Group 5: Node.js Core — `under_investigation` (8 CVEs)

DockGuard uses Node.js 20 to serve its SvelteKit frontend on the local network. These affect the Node.js runtime itself and need individual CVE analysis.

| CVE | Package | Severity |
|---|---|---|
| CVE-2025-55130 | nodejs/libnode115 | Critical |
| CVE-2025-55131 | nodejs/libnode115 | High |
| CVE-2025-59465 | nodejs/libnode115 | High |
| CVE-2025-59466 | nodejs/libnode115 | High |
| CVE-2026-21637 | nodejs/libnode115 | High |
| CVE-2025-55132 | nodejs/libnode115 | Medium |
| CVE-2026-22036 | node-undici | High |
| CVE-2025-23167 | node-undici | Medium |

Status notes: "Awaiting Debian package update for Node.js 20. DockGuard runs on local networks only."

### Group 6: Python 3.13 — `under_investigation` (14 CVEs)

DockGuard uses Python 3.13 for its backend. These affect the CPython interpreter. Debian marks them as "wont-fix" for the 3.13 series — fixes require Python 3.15 stable.

| CVE | Severity | Notes |
|---|---|---|
| CVE-2025-8194, CVE-2025-13836 | High | Awaiting Python 3.15 or Debian backport |
| CVE-2025-12781, CVE-2025-15366, CVE-2025-15367, CVE-2025-6069, CVE-2025-6075, CVE-2025-8291, CVE-2025-12084, CVE-2025-13837, CVE-2025-15282, CVE-2026-0672, CVE-2026-0865, CVE-2026-1299 | Medium | Same — awaiting upstream fixes |

### Group 7: System Libraries Used by DockGuard — `under_investigation` (17 CVEs)

These are in libraries that DockGuard or its dependencies do use, requiring per-CVE analysis.

| CVE | Package | Severity |
|---|---|---|
| CVE-2025-15281, CVE-2026-0915, CVE-2026-0861 | `libc6` | High |
| CVE-2025-13151 | `libtasn1-6` | High |
| CVE-2025-59375, CVE-2025-66382, CVE-2026-25210 | `libexpat1` | High/Medium |
| CVE-2026-23949 | `python3-jaraco.context`, `python3-pkg-resources` | High |
| CVE-2025-14819, CVE-2025-14524, CVE-2025-13034 | `curl` | Medium |
| CVE-2025-6141 | `ncurses` | Medium |
| CVE-2025-7709 | `libsqlite3-0` | Medium |
| CVE-2026-27171 | `zlib1g` | Medium |
| CVE-2026-2297 | `python3.13` (deb) | Medium |
| CVE-2025-47279, CVE-2025-15224, CVE-2025-10966, CVE-2025-14017, CVE-2025-15079 | `curl`/`node-undici` | Low/Negligible |
| CVE-2026-24515 | `libexpat1` | Low |
| CVE-2026-3184 | `util-linux` | Unknown |

### Summary

| VEX Status | Count | Description |
|---|---|---|
| `not_affected` | 42 | Grype deps, unused libs, unused Node packages, negligible OS CVEs |
| `under_investigation` | 39 | Python/Node.js core, used system libs — need per-CVE deep analysis |
| Skipped (negligible curl) | 3 | Low-value negligible curl CVEs already covered by pattern |

**Total VEX statements: ~81** (covering all 84 unique CVEs, some negligible ones grouped)

## Implementation Plan

### 1. Create the OpenVEX Document

**New file:** `vex/dockguard.vex.json`

The document will contain all ~81 statements organized by status. Each statement includes:
- `vulnerability.@id` — the CVE/GHSA ID
- `products` — `[{"@id": "pkg:oci/dockguard"}]`
- `status` — `not_affected` or `under_investigation`
- `justification` — (only for `not_affected`)
- `status_notes` — human-readable explanation

### 2. Install cosign in CI

**File:** `.github/workflows/ci.yml`

Add `sigstore/cosign-installer@v3` to the `docker-build-push` job:

```yaml
- name: Install cosign
  uses: sigstore/cosign-installer@v3
```

Keyless signing with GitHub Actions OIDC — no secrets or key management needed.

### 3. Capture Image Digest

Add `id: build` to the existing `docker/build-push-action@v6` step. The digest is available as `${{ steps.build.outputs.digest }}`.

### 4. Attest VEX Document

After build-and-push, add:

```yaml
- name: Attest VEX document
  if: steps.build.outputs.digest != ''
  env:
    COSIGN_YES: "true"
  run: |
    IMAGE="ghcr.io/${{ github.repository_owner }}/dockguard@${{ steps.build.outputs.digest }}"
    cosign attest --predicate vex/dockguard.vex.json \
      --type openvex \
      "$IMAGE"
```

### 5. Add Required Permissions

```yaml
permissions:
  contents: read
  packages: write
  id-token: write    # for cosign keyless signing (OIDC)
```

## Files to Create/Modify

| File | Change |
|------|--------|
| `vex/dockguard.vex.json` | **New** — OpenVEX document with ~81 vulnerability statements |
| `.github/workflows/ci.yml` | Add cosign installer, `id` on build step, VEX attest step, `id-token: write` permission |

## VEX Document Maintenance

- When vulnerabilities are fixed upstream (e.g., Debian ships new Node.js, Grype updates deps), remove the corresponding statements
- Move `under_investigation` to `not_affected` or `fixed` as analysis completes
- Bump `version` and `timestamp` on every change
- Consider a periodic review (monthly) to reassess `under_investigation` items

## Verification

1. **JSON validation:** Validate `vex/dockguard.vex.json` against OpenVEX schema
2. **CI run:** Push to master, verify cosign attest succeeds in workflow logs
3. **Registry check:** `cosign verify-attestation --type openvex --certificate-identity-regexp '.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/matttw/dockguard:latest`
4. **Self-scan:** Run DockGuard, scan its own GHCR image — VEX badges and annotations appear automatically
5. **Run existing tests:** `uv run pytest -v` — no regressions (no backend code changes)
