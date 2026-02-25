FROM python:3.14.3-slim-trixie

# Install system dependencies needed for grype install script
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install grype (pinned version for reproducible builds)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin v0.109.0

# Copy uv binary from the official image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files first so this layer is cached until deps change
COPY pyproject.toml uv.lock ./

# Install Python dependencies (no dev deps, locked versions)
RUN uv sync --no-dev --frozen

# Copy Alembic config and migrations (needed at runtime for db.init())
COPY alembic.ini ./
COPY alembic/ ./alembic/

# Copy application source
COPY server/ ./server/

# Create the data directory where the SQLite volume will be mounted
RUN mkdir -p /app/data

EXPOSE 8765

CMD ["uv", "run", "uvicorn", "server.api:app", "--host", "0.0.0.0", "--port", "8765"]
