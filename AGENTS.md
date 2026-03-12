Consult ARCHITECTURE.md when you need to understand project architecure and key design decisions.

## Project standards

- Always seek to first use components from the included shadcn component library at frontend/src/lib/components/ui. Do not use other components, or modify components within this library, without explicit permission from the user.
- Changes are not considered complete until all formatters checks, lints, and unit tests pass for both the frontend and backend.

## Validation & Tests

### Backend (Python)

```bash
# 1. Format code
uv run ruff format

# 2. Lint (with auto-fix)
uv run ruff check --fix

# 3. Validation / Lint Check (strict - used in CI)
uv run ruff check

# 4. Unit tests
uv run pytest -v
```

### Frontend (SvelteKit)
Resides in the frontend subdirectory. You may need to change to that directory first.  e.g. cd frontend && npm run format

```bash
# 1. Format code
npm run format

# 2. Lint (with auto-fix)
npm run lint:fix

# 3. Type & Svelte Checks
npm run check

# 4. Validation / Lint Check (strict - used in CI)
npm run lint

# 5. Unit tests (non-watch mode)
npm run test:unit:run
```
