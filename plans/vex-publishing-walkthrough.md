# VEX Publishing for DockGuard — Completion Walkthrough

## What Was Done

DockGuard now publishes OpenVEX attestations alongside its Docker image in GHCR, allowing any VEX-aware tool (including DockGuard itself) to automatically discover and display vulnerability status annotations.

### Files Created

| File | Description |
|------|-------------|
| `vex/dockguard.vex.json` | OpenVEX document with 84 vulnerability statements |

### Files Modified

| File | Changes |
|------|---------|
| `.github/workflows/ci.yml` | Added cosign installer, `id` on build step, VEX attest step, `id-token: write` permission |

---

## VEX Document Details

**Location:** `vex/dockguard.vex.json`

The document covers all 84 unique CVEs found in a fresh scan of the DockGuard Docker image (2026-03-07, Grype v0.109.0):

| VEX Status | Count | What's Covered |
|---|---|---|
| `not_affected` | 40 | Grype compiled-in deps (3), unused Node.js packages (4), unused system libraries (22), negligible ancient CVEs (11) |
| `under_investigation` | 44 | Node.js core (8), Python 3.13 (14), system libraries DockGuard uses (22) |

### `not_affected` Categories

1. **Grype binary deps** (3 CVEs) — GHSA-9h8m-3fm2-qjrq (otel/sdk), GHSA-h395-gr6q-cpjc (jsonwebtoken), GHSA-q9hv-hpm4-hj6x (circl). DockGuard invokes Grype as a subprocess only.

2. **Unused Node.js packages** (4 CVEs) — `node-brace-expansion` (Critical), `node-minimatch` (3x High). DockGuard's SvelteKit server doesn't use glob matching or brace expansion.

3. **Unused system libraries** (22 CVEs) — LDAP, Kerberos, GnuTLS, systemd, tar, Perl, apt, dpkg, shadow-utils, supervisor XML-RPC. None used by DockGuard at runtime.

4. **Negligible ancient CVEs** (11 CVEs) — Disputed/theoretical glibc CVEs from 2010-2019, util-linux, coreutils, SQLite. Debian has classified as not-fixed for years with near-zero real-world impact.

### `under_investigation` Categories

1. **Node.js core** (8 CVEs) — Affects the Node.js runtime itself. DockGuard uses Node.js to serve its SvelteKit frontend. Awaiting Debian package updates.

2. **Python 3.13** (14 CVEs) — Affects the CPython interpreter. Fixes require Python 3.15 stable (not yet released). Debian marks as wont-fix for 3.13 series.

3. **Used system libraries** (22 CVEs) — glibc, curl, libexpat, SQLite, ncurses, zlib, jaraco-context. These are used by DockGuard or its dependencies and need per-CVE analysis to determine actual impact.

---

## CI/CD Changes

### Workflow: `.github/workflows/ci.yml`

**New steps in `docker-build-push` job:**

1. **Install cosign** (`sigstore/cosign-installer@v3`) — Added before the build step
2. **`id: build`** — Added to the build-push-action to capture the image digest
3. **Attest VEX document** — Runs after build, uses keyless signing with GitHub Actions OIDC identity

**New permission:** `id-token: write` — Required for Sigstore's keyless signing (Fulcio certificate issuance via OIDC token)

### How It Works

1. Image is built and pushed to GHCR (existing behavior)
2. `cosign attest` signs the VEX document with the GitHub Actions OIDC identity
3. The attestation is pushed as an OCI artifact referencing the image digest
4. Any tool using the OCI Referrers API can discover the VEX attestation
5. DockGuard's existing VEX discovery code (`backend/vex_discovery.py`) automatically finds and parses it

### Security

- **Keyless signing** — No secret keys to manage. The attestation is signed by a short-lived Fulcio certificate tied to the GitHub Actions workflow identity.
- **Transparency log** — The attestation is logged to Rekor for auditability.
- **Verification** — Anyone can verify the attestation came from the DockGuard GitHub Actions workflow.

---

## Self-Validation (Eating Our Own Dog Food)

After the next CI build pushes the image with the VEX attestation:

1. DockGuard scans its own image from GHCR
2. `backend/vex_discovery.py` queries the Referrers API and finds the OpenVEX attestation
3. VEX statements are matched to vulnerability rows by CVE ID
4. The UI shows:
   - VEX badges on the container card
   - VEX status column in vulnerability tables
   - "VEX Annotated" report option showing all VEX-tagged vulnerabilities
   - "Hide VEX Resolved" toggle to suppress `not_affected` and `fixed` vulns

---

## Maintenance

The VEX document (`vex/dockguard.vex.json`) should be updated when:

- **Upstream fixes land** — Remove fixed CVEs, bump `version` and `timestamp`
- **`under_investigation` items are analyzed** — Move to `not_affected` (with justification) or `affected`
- **New unfixable CVEs appear** — Add new statements
- **Base image changes** — Re-scan and update statements

Recommended: periodic monthly review of `under_investigation` items.

---

## Verification Steps

1. **JSON valid:** `python3 -c "import json; json.load(open('vex/dockguard.vex.json'))"` — confirmed valid, 84 statements, no duplicates
2. **Tests pass:** `uv run pytest -v` — all 88 tests pass, no regressions
3. **CI verification (post-merge):**
   ```bash
   cosign verify-attestation --type openvex \
     --certificate-identity-regexp '.*' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     ghcr.io/matttw/dockguard:latest
   ```
4. **DockGuard self-scan:** After CI, run DockGuard and scan its own GHCR image — VEX annotations should appear automatically
