Consult ARCHITECTURE.md when you need to understand project architecure and key design decisions.

## Project standards

- Always seek to first use components from the included shadcn component library at frontend/src/lib/components/ui. Do not use other components, or modify components within this library, without explicit permission from the user.
- Always use the SvelteKit BFF proxy pattern for API calls from the frontend. Never call backend endpoints directly - route through the BFF proxy routes.
- After making code changes, always run the full test suite before reporting completion. See Validation & Tests section below. Never skip lint/type checking.
- This project uses SQLite. Never use Postgres-specific syntax (UPDATE FROM, etc.). Always verify SQL compatibility with SQLite before writing migrations.
- Prefer simple, straightforward solutions over clever or over-engineered ones. Avoid brittle regex parsing when simple string handling works. When fixing UI issues, check Svelte style scoping before applying CSS overrides.
-mWhen discussing container image digests, never mix manifest_digest and image_id — they are incompatible digest types. Registry digest deduplication must use manifest_digest consistently.
- Do not claim something is supported or already done without verifying in the actual code or documentation first. If unsure, say so.


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

