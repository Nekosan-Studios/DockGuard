# VEX Review Checklist

Use this checklist whenever you edit `vex/dockguard.vex.json`.

## 1) Pick the correct OpenVEX status

Valid OpenVEX statuses:

- `not_affected`
- `affected`
- `fixed`
- `under_investigation`

Decision guide:

- Use `not_affected` only when you can support one of the OpenVEX justifications (for example: code path not used, vulnerable code cannot be controlled by adversary).
- Use `under_investigation` when impact or remediation is still unresolved.
- Use `fixed` only when the product actually includes the remediated version.
- Use `affected` when vulnerability impact is confirmed and unresolved.

## 2) Keep status + notes consistent

- `not_affected` entries must include a `justification` and concrete reason in `status_notes`.
- `under_investigation` entries should not sound final; keep language explicitly open.
- Avoid wording that contradicts status (for example, don't claim "not exploitable" under `under_investigation`).

## 3) Evidence standards for `status_notes`

Prefer evidence that is:

- Source-specific (upstream advisory, distro advisory, package metadata).
- Time-bounded ("as of review date", "current advisory metadata indicates...").
- Component-specific (identify affected runtime/package, not generic app behavior).

Avoid:

- Deployment assumptions (for example, "local networks only", "home-lab only").
- Absolute claims without evidence ("never exploitable", "guaranteed safe").
- Stale statements tied to prerelease timelines unless actively revalidated.

## 4) Writing style guardrails

- Keep notes factual, short, and audit-friendly.
- State what is known, what is unknown, and what is being tracked.
- Prefer: "Current advisory metadata indicates no fixed package is available in the tracked base image at this time."

## 5) Metadata and hygiene

- Increment top-level `version` for substantive VEX updates.
- Update top-level `timestamp` on each review pass.
- Validate JSON after edits.
- Re-scan for stale phrases:
  - `local networks only`
  - `home-lab`
  - `awaiting` (without saying what is being tracked)
  - `wont-fix` (without time/context)

## 6) Suggested review workflow

1. Re-run vulnerability scan and collect current findings.
2. For each statement, verify status against latest evidence.
3. Update `status` / `justification` / `status_notes` together.
4. Bump `version` + `timestamp`.
5. Validate JSON and open a review PR with rationale summary.
