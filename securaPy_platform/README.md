# SecuraPy Platform — SIEM como plataforma de segurança

Evolução do SecuraPy (CLI do 1º semestre) para uma plataforma: **persistência** (MongoDB + MySQL),
**API REST** autenticada (JWT), **machine learning** para priorizar risco, **dashboard web** endurecido
(OWASP), **assistente com LLM** (com fallback) e **alertas em tempo real** por socket — tudo empacotado
com **Docker Compose**. Enunciado: `gs_2semestre.md` do repositório da disciplina.

## Integrantes e divisão de tarefas


| Nome | RM | Responsabilidade (preencher) |
|------|----|------------------------------|
| Gustavo Cesar | 569964| Módulos A + B (núcleo + persistência) |
| Pedro Rossi | 571590 | Módulo C (machine learning) |
| _a preencher_ | | Módulos D + F (API + Docker) |
| Elias Aguiar | 568932 | Módulos E + G (dashboard + LLM) |

## Como executar (Docker)

```bash
cd securaPy_platform
python scripts/gerar_env.py            # cria .env com segredos aleatórios (não vai para o Git)
docker compose up -d --build           # API + MongoDB + MySQL
python scripts/verificar_docker.py http://127.0.0.1:5000   # Módulo F: os 3 contêineres "running"?
python scripts/demo_e2e.py             # login -> análise -> 2 consoles -> IP -> relatório
```

- Dashboard: <http://127.0.0.1:5000> (login = `ADMIN_EMAIL` / `ADMIN_PASSWORD` do `.env`)
- API: `http://127.0.0.1:5000/api/...` · Alertas em tempo real: `python alertas/cliente_alertas.py` (porta 9999)
- Os bancos **não publicam portas** no host; só a API enxerga MongoDB e MySQL (rede `securapy_net`).
- Sem `OPENAI_API_KEY` o assistente usa regras (modo mock) — a arquitetura é a mesma.
- Parar: `docker compose down` (acrescente `-v` para apagar os volumes).

Sem Docker (desenvolvimento): `pip install -r requirements.txt -r requirements-dev.txt`, ter MongoDB/MySQL
acessíveis, preencher o `.env` e rodar `python wsgi.py`.

## Testes (bônus)

```bash
pip install -r requirements-dev.txt
python -m pytest testes -q            # 69 testes
```
Usam MongoDB/MySQL reais se existirem (credenciais em `TEST_MYSQL_PASSWORD`; banco `teste_plataforma`) — sem eles
o MongoDB cai para `mongomock` e os testes de MySQL são pulados.

## Arquitetura

```
securaPy_platform/
├── core/        NÚCLEO (1º sem): coletor, regras, detector, enriquecimento, integridade
├── db/          mongo_repo.py (eventos/alertas)  ·  mysql_repo.py (usuários/permissões)
├── ml/          features · dados_treino · treinar · classificar · anomalias   (+ modelo.pkl, hash, métricas)
├── api/         app.py (rotas, validação, erros) · auth.py (JWT) · seguranca.py (headers, log, limite)
├── ia/          assistente.py (LLM com fallback e defesa contra prompt injection)
├── web/         rotas.py + templates/ (Jinja2 com escape) + static/
├── alertas/     servidor_alertas.py / cliente_alertas.py (TCP, 1º sem; roda numa thread da API)
├── servicos/    analise.py (orquestração) · bootstrap.py (composição)
├── scripts/     gerar_env · ingestao · verificar_docker · demo_e2e
├── config/      regras.json · blacklist.txt          logs/  dados de teste
├── Dockerfile · docker-compose.yml · requirements.txt · wsgi.py · settings.py
```

Fluxo (`POST /api/analisar`): `coletor → regras → detector (brute force, port scan, blacklist, janela temporal)
→ MongoDB → features por IP → ML (score) → alertas CRÍTICOS por socket`. Contrato entre módulos: o **evento**
`{timestamp, fonte, tipo, ip, detalhes, linha_original}` e o **alerta** `{timestamp, regra_id, regra_nome,
severidade, ip, descricao}` — os mesmos dicionários do 1º semestre.

### O que foi reaproveitado do 1º semestre

`coletor.py`, `regras.py`, `detector.py` (inclui `detectar_brute_force_temporal`), `enriquecimento.py`,
`integridade.py` (SHA-256 — agora também protege o modelo de ML), `servidor_alertas.py`, `cliente_alertas.py`,
`config/regras.json` e os 3 logs. Alterações mínimas: `detector` passou a importar `core.regras`; o servidor de
alertas ganhou `parar`/`pronto` e `iniciar_em_thread()` para rodar dentro da API (com histórico limitado a 500).

## API

| Rota | Auth | Descrição |
|------|------|-----------|
| `GET /api/health` | — | estado da API, MongoDB e MySQL (200/503) |
| `POST /api/login` | — | `{email, senha}` → JWT (HS256, 1 h); 401 genérico, 429 após 5 falhas |
| `GET /api/eventos` | leitura* | filtros `fonte, tipo, ip, desde, ate` + `pagina, tamanho` (teto 100) |
| `GET /api/alertas` · `/api/alertas/<id>` | leitura* | filtros `severidade, ip` + paginação; id inválido → 400 |
| `POST /api/alertas` | **token** | cria alerta manual (validado); crítico é transmitido por socket |
| `POST /api/analisar` | **token** | `{}` (logs padrão), `{"caminho": "sub/pasta"}` ou `{"eventos": [...]}` |
| `GET /api/ip/<ip>` | leitura* | eventos + alertas + geolocalização + score ML + explicação do LLM |
| `GET /api/resumo` · `/api/relatorio` | leitura* | agregações e relatório JSON exportável |
| `/api/usuarios` (GET/POST/PUT/DELETE) | token nível 5 | CRUD de operadores (MySQL) |

\* leitura é pública por padrão (conforme o enunciado); `EXIGIR_AUTH_LEITURA=1` exige token também nela.
Status usados: 200, 201, 400 (entrada inválida, nunca 500), 401, 403, 404, 409, 429, 503, 500 (genérico).

## Segurança (mapa para o OWASP Top 10:2025)

| Controle | Onde | OWASP |
|---|---|---|
| Queries parametrizadas; login `' OR '1'='1` neutralizado | `db/mysql_repo.py` | A05 |
| Escape de saída (Jinja2 sem `\|safe`), CSP, CSRF em todo POST | `web/` | A05, A02 |
| Headers `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` em **todas** as respostas | `api/seguranca.py` | A02 |
| JWT com algoritmo fixo, `exp/iss` obrigatórios; sessão HttpOnly + SameSite | `api/auth.py` | A07 |
| Login genérico (anti-enumeração), hash scrypt, hash "falso" para igualar tempo, limite de tentativas | `mysql_repo`, `api`, `web` | A07 |
| Controle de acesso por nível (401 × 403); `caminho` de logs restrito à pasta permitida | `api/auth.py`, `servicos/analise.py` | A01 |
| Segredos só no ambiente (`.env` fora do Git); sem senha no código | `settings.py` | A02/A04 |
| Hash SHA-256 do modelo verificado **antes** do `joblib.load` | `ml/classificar.py` | A08 |
| Log de cada requisição, de falhas de login e de ações sensíveis | `api/seguranca.py` | A09 |
| Erros sem traceback/query/segredo; 503 amigável se um banco cair; evento malformado não derruba o lote | `api/app.py`, repos | A10 |
| Contêiner sem root, bancos sem porta publicada, healthchecks | `Dockerfile`, compose | A02 |
| LLM: entrada redigida e delimitada, saída validada, **nunca rebaixa** o veredito das regras | `ia/assistente.py` | LLM01 |

## Machine learning

`ml/treinar.py` → `Pipeline(StandardScaler + RandomForest)`, validação cruzada de 5 folds e métricas no teste
(precisão 0,93 · recall 0,96 · F1 0,95; ver `ml/metricas.json`), `modelo.pkl` + `modelo.pkl.sha256`.
Features por IP: nº de FAILs, portas distintas bloqueadas, presença na blacklist, requisições web com erro,
total de eventos. Resultado nos logs reais: `185.220.101.1` → **ALTO / ataque**, `192.168.1.10` → **BAIXO / normal**.

> ⚠️ **Os dados de treino são sintéticos** (`ml/dados_treino.py`, seed fixa): não existe base rotulada real, e os
> 3 logs têm só ~10 IPs. As métricas medem o modelo sobre esse gerador, não sobre tráfego real.
> O bônus de **Isolation Forest** (`ml/anomalias.py`) não usa rótulos.

## Cenários de teste do enunciado

| # | Onde está verificado |
|---|---|
| A1–A4 | `testes/test_modulo_a_core.py` — o `auth.log` tem **11** FAILs de `185.220.101.1` (o enunciado diz 10); severidade ALTA |
| B1–B4 | `testes/test_modulo_b_c_db_ml.py` — 58 eventos (23+17+18), top IP, e-mail duplicado, SQLi |
| C1–C4 | idem — métricas, score ALTO/BAIXO, hash do modelo |
| D1–D5 | `testes/test_modulo_d_api.py` |
| E1–E4 | `testes/test_modulo_e_web.py` |
| F1–F3 | `docker compose up` + `scripts/verificar_docker.py` + `scripts/demo_e2e.py`; teste unitário em `test_modulo_g_f_alertas_docker.py` |
| G1–G4 | `testes/test_modulo_g_f_alertas_docker.py` |

## Bônus implementados

Isolation Forest (+0,30) · correlação temporal na análise (+0,20) · testes `pytest` (+0,30) · JWT completo (+0,20).

## Limitações conhecidas

- Sem `OPENAI_API_KEY`, as respostas do "LLM" vêm do mock/regras (campo `origem` informa isso). Nada foi testado
  contra a API real da OpenAI.
- Alertas em tempo real, limitador de tentativas e cache de geolocalização ficam em memória de **um** processo
  (`--workers 1`); para escalar é preciso externalizá-los (ex.: Redis).
- `Secure` do cookie e HTTPS dependem de proxy reverso (`COOKIE_SEGURO=1`).
- O vídeo de apresentação (entregável 3) e a tabela de integrantes precisam ser feitos pelo grupo.

## Entregáveis

1. Código: esta pasta · 2. README: este arquivo · 3. Vídeo: **a gravar** · 4. Relatório de exemplo:
[saida/relatorio_exemplo.json](saida/relatorio_exemplo.json) · 5. Modelo: [ml/modelo.pkl](ml/modelo.pkl),
[hash](ml/modelo.pkl.sha256), [métricas](ml/metricas.json).
