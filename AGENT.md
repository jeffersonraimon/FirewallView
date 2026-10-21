# 🤖 Diretrizes de Arquitetura e Consistência (AI & Contribuidores)

> **Importante para IAs e Desenvolvedores**: Este documento estabelece as regras, convenções arquiteturais e padrões de consistência do **FirewallView**. Qualquer modificação, novo parser, novo componente de UI ou refatoração DEVE seguir rigorosamente as definições contidas aqui para preservar a integridade, usabilidade e precisão técnica da aplicação.

---

## 🎯 1. Propósito e Filosofia do Projeto

- **Simulador Preciso**: O FirewallView não é apenas um exibidor de tabelas; ele executa uma **simulação matemática e lógica determinística** do fluxo de pacotes em redes de computadores.
- **Minimalismo e Ergonomia**: Interface limpa, confortável aos olhos (dark mode de alto contraste controlado), sem poluição visual ou complexidade desnecessária.
- **Multi-Plataforma por Design**: O FirewallView deve tratar MikroTik RouterOS (v6/v7), Linux iptables/ipset, nftables e Cisco ACL como cidadãos de primeira classe, mantendo paridade de recursos e capacidade de conversão cruzada entre eles.

---

## 🏗️ 2. Arquitetura do Sistema

```text
FirewallView/
├── backend/
│   ├── firewallview/
│   │   ├── engine/          # Motor de simulação lógica e matchers
│   │   ├── parsers/         # Parsers para sintaxes externas
│   │   ├── exporters/       # Conversores/exportadores de regras
│   │   ├── models/          # Modelos de dados Pydantic (imutáveis e tipados)
│   │   ├── samples/         # Presets canônicos (RouterOS, iptables, Cisco)
│   │   └── main.py          # API FastAPI e static server
│   ├── tests/               # Testes automatizados (pytest)
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/      # Componentes visuais desacoplados
│   │   ├── api/             # Client HTTP para backend
│   │   ├── types/           # Interfaces TypeScript canônicas
│   │   ├── App.tsx          # Estado global e orquestração
│   │   └── index.css        # Tailwind CSS e estilos globais
│   ├── package.json
│   └── vite.config.ts
├── Dockerfile               # Multi-stage build (Node -> Python slim)
├── docker-compose.yml       # Orquestração do contêiner único na porta 8080
└── run.sh                   # Script executável padrão
```

---

## ⚙️ 3. Regras do Motor de Simulação (`engine/`)

### Pipeline de Decisão Canônico
O fluxo de pacotes deve respeitar rigorosamente a ordem do kernel/SO:

1. **Tráfego em Trânsito (Forward)**:
   `PREROUTING (Raw)` ➔ `PREROUTING (Mangle)` ➔ `PREROUTING (Dst-NAT)` ➔ `Routing Decision (Forward)` ➔ `FORWARD (Mangle)` ➔ `FORWARD (Filter)` ➔ `POSTROUTING (Mangle)` ➔ `POSTROUTING (Src-NAT)` ➔ `Delivered / Outbound`

2. **Tráfego Local (Input)**:
   `PREROUTING (Raw)` ➔ `PREROUTING (Mangle)` ➔ `PREROUTING (Dst-NAT)` ➔ `Routing Decision (Local Process)` ➔ `INPUT (Mangle)` ➔ `INPUT (Filter)` ➔ `Local Inbound`

### Tipos de Ações e Efeitos
- **Terminantes**:
  - `drop`: Interrompe imediatamente o fluxo em qualquer estágio. Veredito final = `DROP`.
  - `reject`: Interrompe o fluxo e sinaliza ICMP Unreachable. Veredito final = `REJECT`.
  - `accept`: Na tabela `filter`, encerra a verificação de filtragem e permite que o pacote avance para as etapas pós-roteamento / entrega.
- **Transformações (NAT)**:
  - `dst-nat`: Modifica `packet.dst_ip` e/ou `packet.dst_port` e continua a avaliação.
  - `src-nat` / `masquerade`: Modifica `packet.src_ip` e continua a avaliação.
- **Saltos e Retornos**:
  - `jump`: Executa a cadeia apontada em `target_chain`. Proteja SEMPRE contra recursão infinita ou loops circulares via `call_stack`.
  - `return`: Encerra a cadeia atual e retorna o controle para a regra seguinte da cadeia de origem.
- **Não-Terminantes**:
  - `mark-packet`, `mark-connection`, `mark-routing`, `log`, `passthrough`: Aplicam seu efeito e continuam para a próxima regra.

### Matchers de Rede (`matcher.py`)
- **Nunca use comparações ingênuas de string para IPs**: Use a biblioteca nativa `ipaddress` para lidar com:
  - IPs individuais (`192.168.1.1`)
  - Subnets CIDR (`192.168.0.0/24`, `10.0.0.0/8`)
  - Ranges numéricos (`10.0.0.1-10.0.0.50`)
  - Address Lists / IPsets
- **Negações**: Sempre suporte o operador `!` para todos os matchers (`!src-address`, `!dst-port`, `!protocol`, `!in-interface`).
- **Explicabilidade**: Cada regra avaliada DEVE registrar sua justificativa em `RuleEvaluation.reasons` (ex: `"Dst-Port 80 != 443 -> Mismatch"` ou `"Src-IP 10.5.5.5 matched list 'BOGONS'"`).

---

## 🔌 4. Padrões de Parsers e Exporters

Ao adicionar ou modificar regras para qualquer firewall suportado:
1. **Parsers** devem aceitar comentários, linhas vazias, variações de maiúsculas/minúsculas e parâmetros em ordens arbitrárias.
2. Todo novo campo adicionado em `RuleCondition` ou `FirewallRule` DEVE ser implementado em **todos os 4 parsers e exporters**:
   - `routeros.py`
   - `iptables.py`
   - `nftables.py`
   - `cisco.py`
3. Cada mudança nos parsers DEVE ser acompanhada de testes unitários correspondentes em `backend/tests/`.

---

## 🎨 5. Padrões Visuais e Design System (UI/UX)

- **Paleta de Cores Semântica (Obrigatória)**:
  - 🟢 **Verde Esmeralda (`emerald-400` / `emerald-950`)**: Veredito `ACCEPT`, regras que deram `MATCH` com sucesso, botões de exportação.
  - 🔴 **Vermelho Rosa/Coral (`rose-400` / `rose-950`)**: Veredito `DROP`, pacotes barrados, avisos de erro e exclusão.
  - 🟠 **Laranja / Âmbar (`amber-400` / `amber-950`)**: Veredito `REJECT`, transformações `NAT` (DNAT/SNAT), TCP Flags.
  - 🔵 **Ciano / Azul Elétrico (`cyan-400` / `cyan-600`)**: Identidade visual, ações primárias, inputs de rede de origem, interfaces.
  - 🟣 **Violeta / Roxo (`violet-400` / `violet-950`)**: Address Lists, IPsets, Sets e grupos de objetos.
  - ⬛ **Fundo Dark Slate (`slate-950`, `slate-900`, `slate-800`)**: Garantir legibilidade sem ofuscar a visão.
- **Fontes**:
  - Elementos de rede (IPs, portas, protocolos, flags, comandos brutos) SEMPRE com `font-mono`.
  - Textos de interface e comentários com `font-sans`.
- **Interatividade**:
  - Auto-simulação com debounce (250ms) ativa por padrão para resposta instantânea ao digitar.
  - Destaque interativo no pipeline de nós: clicar em um nó filtra a tabela de regras correspondente.

---

## 📦 6. Docker e Empacotamento

- O contêiner de produção DEVE ser executável com um comando único:
  ```bash
  docker compose up -d --build
  ```
- O contêiner roda Frontend estático e Backend FastAPI em um único processo leve uvicorn na porta **8080**.
- **Nunca** adicione arquivos temporários de build (`dist/`, `node_modules/`, `.venv/`) ao repositório git. Eles devem permanecer no `.gitignore` e `.dockerignore`.
- O código do backend deve usar **importação absoluta** (`from firewallview.engine import ...`) para evitar conflitos de namespace com bibliotecas externas.

---

## ✅ 7. Checklist para Novos Recursos

Antes de finalizar qualquer modificação no código:
- [ ] O backend roda `PYTHONPATH=. pytest tests/` com 100% dos testes passando?
- [ ] O frontend compila sem nenhum erro TypeScript (`npm run build`)?
- [ ] O contêiner Docker sobe limpo na porta 8080 e responde na rota raiz `/` e em `/api/health`?
- [ ] A consistência visual segue estritamente a paleta semântica definida na seção 5?
- [ ] A documentação no `README.md` reflete fielmente as novas funcionalidades?
