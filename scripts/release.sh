#!/bin/bash
# Wrapper script to make bumping versions easier.

# Check if uv is installed, if so use it, otherwise fall back to standard python3
if command -v uv &> /dev/null; then
    uv run python scripts/bump_version.py "$@"
else
    python3 scripts/bump_version.py "$@"
fi
