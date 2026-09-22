# MESI SOCHAI Dashboard

Plataforma de SOCHAI (Security Operations Center Human Artificial Inteligence) com componente de treino gamificado para colaboradores e analistas júnior, desenvolvida no âmbito do **Mestrado em
Engenharia de Segurança Informática (MESI)** — ano letivo 2025/26,
Instituto Politécnico de Beja (IPBeja).

> ⚠️ **Projeto académico / educativo.** Todos os dados (eventos, logs, IPs,
> domínios) são **sintéticos**. Não contém qualquer informação real de
> produção, de utilizadores ou de organizações. IPs em ranges RFC1918 /
> TEST-NET; domínios `.example` / `.test`.

---

## Objetivo

Disponibilizar um ambiente de SOCHAI funcional, inspirado em soluções como o
Cortex XSIAM, que sirva simultaneamente para:

- **Operação:** ingestão e normalização de eventos, correlação e deteção
  mapeada à matriz MITRE ATT&CK, e visualização de alertas em tempo real.
- **Treino:** ambiente gamificado (missões, desafios CTF, XP, ranks, badges)
  para desenvolvimento de competências de colaboradores e analistas em formação.

---

## Arquitetura

O sistema organiza-se em camadas:

```
app/
  api/      # endpoints REST + WebSocket (alertas em tempo real)
  ingest/   # parsers e normalização de eventos (schema ECS-like)
  detect/   # motor de correlação + regras YAML (MITRE ATT&CK)
  gamify/   # XP, ranks, badges, leaderboard, missões
  db/       # acesso SQLite, schema, migrações
config/
  missions.yaml   # definição das missões de treino
  rules/          # regras de correlação
tests/
  fixtures/       # dados sintéticos para testes
```

O fluxo principal: os eventos entram pela camada de **ingestão**, são
normalizados para um schema comum, percorrem o **motor de deteção** (que
gera alertas anotados com a técnica ATT&CK correspondente) e são entregues
ao **dashboard** via WebSocket. As ações dos analistas alimentam a camada
de **gamificação**.

---

## Stack tecnológico

| Componente        | Tecnologia            |
|-------------------|-----------------------|
| Backend / API     | FastAPI               |
| Tempo real        | WebSockets            |
| Base de dados     | SQLite                |
| Validação         | Pydantic              |
| Frontend          | JavaScript (vanilla)  |
| Testes            | pytest                |
| Lint / formatação | ruff · black · mypy   |

---

## Requisitos

- Python 3.11+
- Ambiente virtual recomendado (`.venv`)

---

## Instalação e execução

```bash
# Clonar e entrar no projeto
git clone https://github.com/<user>/mesi-soc-dashboard.git
cd mesi-soc-dashboard

# Ambiente virtual
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Dependências
pip install -r requirements.txt

# Variáveis de ambiente (copiar e preencher)
cp .env.example .env

# Arrancar o servidor
uvicorn app.api.main:app --reload
```

O dashboard fica disponível em `http://127.0.0.1:8000`.

---

## Acessos e níveis de permissão

O dashboard (`streamlit run dashboard.py`) tem agora ecrã de início de sessão
(módulo [`auth.py`](./auth.py)). Há dois níveis:

| Nível         | Acesso |
|---------------|--------|
| `staff`       | Plataforma SOC completa (todas as tabs) + gestão de acessos |
| `colaborador` | Apenas **Gamificação**, **Playbooks** e **Incidentes** (vista de acompanhamento — em curso / por resolver / resolvidos, só leitura) — ver [`portal_colaborador.py`](./portal_colaborador.py) |

Credenciais iniciais (criadas no primeiro arranque em `users_auth.json`, que
**não** é versionado):

| Utilizador    | Palavra-passe | Nível        |
|---------------|---------------|--------------|
| `admin`       | `sochai123`   | staff        |
| `analista`    | `sochai123`   | staff        |
| `colaborador` | `colab123`    | colaborador  |

Um utilizador `staff` cria novos acessos de colaborador na barra lateral
(**👥 Gerir acessos ao portal**). As palavras-passe são guardadas apenas como
hash SHA-256.

---

## Testes

```bash
pytest                 # suite completa
pytest tests/detect/   # apenas um módulo
```

Todos os testes usam exclusivamente fixtures sintéticos em `tests/fixtures/`.

---

## Convenções de desenvolvimento

As regras do projeto (dados sintéticos, validação Pydantic, SQL
parametrizado, idempotência da gamificação, testes obrigatórios) estão
documentadas em [`CLAUDE.md`](./CLAUDE.md). As permissões da ferramenta de
assistência estão em `.claude/settings.json`.

---

## Contexto académico

| | |
|---|---|
| **Mestrado** | Engenharia de Segurança Informática (MESI) |
| **Instituição** | Instituto Politécnico de Beja (IPBeja) |
| **Ano letivo** | 2025/26 |

---

## Licença

Projeto de natureza académica. Utilização sujeita a autorização.
