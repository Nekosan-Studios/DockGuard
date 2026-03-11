Consult ARCHITECTURE.md to understand project architecure and key design decisions.

## Project standards

- Always seek to first use components from the included shadcn component library at frontend/src/lib/components/ui. Do not use other components, or modify components within this library, without explicit permission from the user.
- Changes are not considered complete until all checks, lints, prettiers, and unit tests pass for both the frontend and backend.

## Running Tests
 
```bash
# Backend unit tests
uv run pytest -v

# Frontend
cd frontend && npm run lint        # ESLint
cd frontend && npm run lint:fix    # ESLint with auto-fix
cd frontend && npm run format      # Prettier (write)
cd frontend && npm run check       # svelte-check / TypeScript
cd frontend && npm run test:unit   # Vitest unit tests
```
