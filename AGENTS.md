Consult ARCHITECTURE.md when you need to understand project architecure and key design decisions.

## Project standards

- Always seek to first use components from the included shadcn component library at frontend/src/lib/components/ui. Do not use other components, or modify components within this library, without explicit permission from the user.
- Changes are not considered complete until all formatters checks, lints, and unit tests pass for both the frontend and backend.

## Vulnerability table layout guardrails

These rules are important and should be preserved unless the user explicitly asks to change them:

- The vulnerability table is used in 3 contexts:
	- Main Vulnerabilities page (`frontend/src/routes/vulnerabilities/+page.svelte`)
	- Container expanded sub-view (`frontend/src/lib/components/vuln/ContainerRow.svelte`)
	- Preview Scan dialog (`frontend/src/lib/components/preview/PreviewScannerModal.svelte` + nested `ContainerRow`)
- Prefer column rebalancing before adding new wrappers or per-view special-case hacks.
- Preserve this sizing intent:
	- Non-description columns keep readable minimums.
	- Description column absorbs remaining/free space first.
	- Horizontal scrolling is acceptable only after those minimums are reached.
- In Preview Scan dialog specifically:
	- First try fitting by allocating more dialog width and explicit outer table columns.
- Avoid brittle nested selector hacks (for example, deep `table table` CSS overrides) when a scoped structural sizing fix is possible.
- When adjusting one table context, check the other two for regressions before finalizing.

## Validation & Tests

### Backend (Python)

One-liner (run from project root):
```bash
uv run ruff format && uv run ruff check --fix && uv run ruff check && uv run pytest -v 2>&1 | tail -20
```

### Frontend (SvelteKit)

One-liner (run from project root):
```bash
cd frontend && npm run format && npm run lint:fix && npm run check && npm run lint && npm run format:check && npm run test:unit:run 2>&1 | tail -30
```

