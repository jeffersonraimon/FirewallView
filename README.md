# FirewallView 🛡️

**FirewallView** é uma aplicação moderna, minimalista e visualmente confortável projetada para **simular, inspecionar e testar o fluxo de pacotes através de regras de firewall**.

Ele permite validar previamente como pacotes de rede (TCP, UDP, ICMP, etc.) se comportam diante de tabelas de firewall complexas, analisando cada estágio do pipeline de decisão (Raw, Mangle, NAT, Routing, Filter) e inspecionando o veredito exato (ACCEPT, DROP, REJECT, NAT) e o motivo de match de cada regra.

---

## ✨ Recursos Principais

- **Simulação Interativa de Fluxo (Packet Trace & Inspector)**:
  - Defina pacotes de teste com IPs de origem/destino, portas, protocolo, interfaces (`in-interface`, `out-interface`), connection states (`new`, `established`, `related`, `invalid`) e flags TCP (`SYN`, `ACK`, `FIN`, `RST`, etc.).
  - Presets rápidos para 1 clique (Acesso Web LAN → WAN, SSH de Admin, Ataque Bogon / Botnet, Port Forwarding NAT, Ping ICMP).
  - Veredito imediato com destaque visual e detalhamento do motivo de match/mismatch por critério.

- **Suporte Multi-Sintaxe de Firewall**:
  - **MikroTik RouterOS (v6 e v7)**: `/ip firewall filter`, `/ip firewall nat`, `/ip firewall mangle`, `/ip firewall raw`, `/ip firewall address-list`.
  - **Linux iptables & ipset**: Regras `iptables -A ...`, `iptables-save`, `ipset create/add`, suporte a `-m set --match-set`.
  - **nftables**: Sintaxe declarativa e em blocos `table inet filter { chain input { ... } }`, sets (`@list`), hooks e priorities.
  - **Cisco ACL & ASA**: `access-list` standard/extended, named ACLs `ip access-list extended`, e `object-group network`.

- **Gerenciador de Address Lists & IPsets**:
  - Suporte a IPs únicos (`10.0.0.1`), prefixos CIDR (`192.168.0.0/24`), ranges (`10.0.0.1-10.0.0.50`).
  - Testador interativo para verificar se qualquer endereço IP pertence a uma ou mais listas.

- **Importação e Exportação / Conversor de Sintaxes**:
  - Importe scripts ou regras colando o texto ou enviando arquivos (`.rsc`, `.sh`, `.nft`, `.txt`) com **detecção automática** da sintaxe.
  - Exporte ou converta suas regras para qualquer um dos formatos suportados com 1 clique (ex: converta regras de MikroTik para iptables ou Cisco ACL).

- **Visualizador Visual do Pipeline**:
  - Grafo visual horizontal dos nós do kernel/sistema operacional:
    `PREROUTING (Raw)` ➔ `PREROUTING (Mangle)` ➔ `PREROUTING (Dst-NAT)` ➔ `Routing Decision` ➔ `FORWARD / INPUT (Filter)` ➔ `POSTROUTING (Mangle)` ➔ `POSTROUTING (Src-NAT)`.
  - Exibição de transformações em tempo real (DNAT e SNAT / Masquerade).

- **100% Dockerizado**:
  - Empacotado em um contêiner leve contendo Frontend compilado + Backend FastAPI de alta performance.

---

## 🚀 Como Executar com Docker

### 1. Início Rápido (Recomendado)

Clone o repositório ou acesse a pasta do projeto e execute:

```bash
./run.sh
```

Ou diretamente via Docker Compose:

```bash
docker compose up -d --build
```

A aplicação estará disponível em:
👉 **[http://localhost:8080](http://localhost:8080)**

Para parar o contêiner:
```bash
docker compose down
```

---

## 💻 Desenvolvimento Local (Opcional)

Se desejar rodar fora do Docker durante o desenvolvimento:

### Backend (Python 3.12+):
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=. uvicorn firewallview.main:app --reload --port 8080
```

### Frontend (Node 20+):
```bash
cd frontend
npm install
npm run dev
```
Acesse o frontend em `http://localhost:3000` (com proxy automático configurado para o backend na porta 8080).

---

## 🧪 Testes Unitários

Para rodar os testes automatizados dos parsers e do simulador:

```bash
cd backend
PYTHONPATH=. pytest tests/
```

---

## 📂 Estrutura do Projeto

```text
FirewallView/
├── backend/
│   ├── firewallview/
│   │   ├── engine/          # Motor de simulação e matchers de IP/Porta/Estado
│   │   ├── parsers/         # Parsers para RouterOS v6/v7, iptables, nftables, Cisco
│   │   ├── exporters/       # Exporters e conversores de sintaxe
│   │   ├── models/          # Modelos Pydantic (Regras, Pacotes, Address Lists)
│   │   ├── samples/         # Presets prontos (MikroTik, iptables, Cisco)
│   │   └── main.py          # API FastAPI e servidor estático
│   ├── tests/               # Testes automatizados com Pytest
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/      # UI (Pipeline visual, Simulator, Rules table, Modais)
│   │   ├── api/             # Cliente de comunicação com a API
│   │   ├── types/           # Tipos TypeScript
│   │   ├── App.tsx          # Aplicação principal
│   │   └── index.css        # Tailwind CSS
│   ├── package.json
│   └── vite.config.ts
├── Dockerfile               # Build multi-stage otimizado
├── docker-compose.yml       # Orquestração do contêiner
├── run.sh                   # Script executável de inicialização
└── README.md                # Documentação
```
