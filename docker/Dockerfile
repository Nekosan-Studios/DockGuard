# ── Stage 1: Frontend Builder ──────────────────────────────────────────
FROM node:24.14.1-alpine AS frontend-builder

WORKDIR /app/frontend

# Install deps first for caching
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

# Patch transitive dependency vulnerabilities (|| true: remaining unfixable ones require breaking changes)
RUN npm audit fix || true

# Copy source and build
COPY frontend/ .
RUN npm run check
RUN npm run build

# Prune devDependencies
RUN npm prune --omit=dev

# ── Stage 2: Backend & Base Image ──────────────────────────────────────
FROM dhi.io/python:3.14.4-dev

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gzip \
    supervisor \
    nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin v0.110.0

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install Python dependencies & pre-compile bytecode so first startup is fast
RUN uv sync --no-dev --frozen --compile-bytecode

# Bake version from git tag when provided (e.g. --build-arg APP_VERSION=1.2.3)
ARG APP_VERSION=""
ENV APP_VERSION=${APP_VERSION}

# Copy application source
COPY backend/ ./backend/
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Copy frontend build from Stage 1
COPY --from=frontend-builder /app/frontend/build ./frontend/build
COPY --from=frontend-builder /app/frontend/node_modules ./frontend/node_modules
COPY --from=frontend-builder /app/frontend/package.json ./frontend/
COPY frontend/log-timestamps.cjs ./frontend/

# Create data directory
RUN mkdir -p /app/data

# Persist Grype DB cache
ENV GRYPE_DB_CACHE_DIR=/app/data/grype_db

EXPOSE 8765 8764

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
