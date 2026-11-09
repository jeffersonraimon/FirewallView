# ==========================================
# Stage 1: Build Frontend (Vite + React)
# ==========================================
FROM node:24-alpine AS frontend-builder
WORKDIR /build

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# ==========================================
# Stage 2: Production Runtime (FastAPI + Static)
# ==========================================
FROM python:3.12-slim

LABEL maintainer="FirewallView"
LABEL description="FirewallView - Simulador e Validador Visual de Regras de Firewall"

WORKDIR /app

# Install runtime Python dependencies only (pytest/httpx live in requirements-dev.txt)
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy Backend application
COPY backend/firewallview /app/firewallview

# Copy built frontend assets from Stage 1
COPY --from=frontend-builder /build/dist /app/frontend/dist

# Run as an unprivileged user
RUN useradd --system --no-create-home --uid 10001 firewallview \
    && chown -R firewallview:firewallview /app
USER firewallview

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT', '8080'), timeout=3)"]

# Run uvicorn server (honors $PORT)
CMD ["sh", "-c", "exec uvicorn firewallview.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
