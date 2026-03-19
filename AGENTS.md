Consult ARCHITECTURE.md when you need to understand project architecure and key design decisions.

## Project standards

- Always seek to first use components from the included shadcn component library at frontend/src/lib/components/ui. Do not use other components, or modify components within this library, without explicit permission from the user.
- Changes are not considered complete until all formatters checks, lints, and unit tests pass for both the frontend and backend.


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

