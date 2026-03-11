Consult ARCHITECTURE.md to understand project architecure and key design decisions.

## Project standards

- Always seek to first use components from the included shadcn component library at frontend/src/lib/components/ui. Do not use other components, or modify components within this library, without explicit permission from the user.
- Changes are not considered complete until all checks and unit tests pass for both the frontend and backend.

## Running Tests
 
```bash
# Backend unit tests
uv run pytest -v

# Frontend unit tests
cd frontend && npm run test

# Frontend type checking
cd frontend && npm run check
```
