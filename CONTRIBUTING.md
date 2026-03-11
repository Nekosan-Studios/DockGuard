# Contributing to DockGuard

Thanks for your interest in contributing. DockGuard is a small project and contributions of all kinds are welcome — bug reports, feature ideas, documentation improvements, and code.

## Reporting Bugs

Please open a [GitHub issue](https://github.com/matttw/dockguard/issues) with:

- A clear description of what happened vs. what you expected
- Steps to reproduce
- Your Docker and OS version
- Relevant logs (`docker compose logs dockguard`)

## Suggesting Features

Open a GitHub issue with the `enhancement` label. Describe the problem you're trying to solve, not just the solution — this makes it easier to discuss the best approach.

## Development Setup

See [DEVELOPING.md](DEVELOPING.md) for a full guide to setting up your local environment, running tests, and understanding the project structure.

## Pull Requests

1. **Open an issue first** for anything non-trivial. This avoids wasted effort if the direction isn't a fit.
2. **Fork the repo** and create a branch from `master`:
   ```bash
   git checkout -b your-feature-name
   ```
3. **Make your changes** with tests where applicable.
4. **Run the test suite** before opening a PR:
   ```bash
   uv run pytest -v
   cd frontend && npm run test && npm run check
   ```
5. **Open a pull request** against `master` with a clear description of what changed and why.

## What Makes a Good PR

- Focused — one thing per PR
- Tested — new behaviour has corresponding tests; existing tests still pass
- Clean — no leftover debug code, commented-out blocks, or unrelated changes
- Described — the PR description explains the motivation, not just the diff

## Code Style

**Python:** No strict formatter enforced currently, but follow the existing style (4-space indentation, type hints on function signatures, docstrings on public methods).

**TypeScript / Svelte:** Follow the patterns in the existing components. Run `npm run check` to catch type errors.

## Questions

If you're unsure whether something is a good fit or how to approach a change, open an issue and ask — it's the easiest way to get quick feedback before investing time in an implementation.
