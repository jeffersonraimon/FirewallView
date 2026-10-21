#!/usr/bin/env bash
set -e

echo "================================================="
echo "       Iniciando FirewallView em Docker          "
echo "================================================="

cd "$(dirname "$0")"

# Build and start container
docker compose up -d --build

echo ""
echo "✅ FirewallView está rodando com sucesso!"
echo "🌐 Acesse no seu navegador: http://localhost:8080"
echo ""
echo "Para visualizar os logs: docker compose logs -f"
echo "Para parar a aplicação: docker compose down"
echo "================================================="
