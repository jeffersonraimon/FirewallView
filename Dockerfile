# ==========================================
# Stage 1: Build Frontend (Vite + React)
# ==========================================
FROM node:20-alpine AS frontend-builder
WORKDIR /build

COPY frontend/package.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# ==========================================
# Stage 2: Production Runtime (FastAPI + Static)
# ==========================================
FROM python:3.12-slim

LABEL maintainer="FirewallView"
LABEL description="FirewallView - Simulador e Validador Visual de Regras de Firewall"

WORKDIR /app

# Install Python dependencies
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy Backend application
COPY backend/firewallview /app/firewallview

# Copy built frontend assets from Stage 1
COPY --from=frontend-builder /build/dist /app/frontend/dist

ENV PYTHONPATH=/app
ENV PORT=8080

EXPOSE 8080

# Run uvicorn server
CMD ["uvicorn", "firewallview.main:app", "--host", "0.0.0.0", "--port", "8080"]
