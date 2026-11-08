# CLAUDE.md — contexto do repositório SecuraPy

Leia este arquivo antes de mexer no código. Ele descreve o que existe, como as peças se encaixam, como rodar/testar
e as armadilhas já encontradas. Idioma do projeto: **português** (código, comentários, mensagens, commits).

## 1. O que é este repositório

Trabalhos da disciplina **Coding for Security** (FIAP, prof. Fabio Bara) — um SIEM didático chamado **SecuraPy**.
Enunciados oficiais ficam em `https://github.com/fabioBaraDev/coding_for_security` (`apostila_2semestre.md`,
`cp1_2semestre.md`, `cp2_cumulativo_2semestre.md`, `gs_2semestre.md`); **não estão neste repo**.

```
securaPy/
├── GS_1Semestre/securaPy/   1º semestre: SIEM em CLI (JÁ implementado, 197 testes). NÃO é o foco hoje.
├── GS_2Semestre/            2º semestre: exercícios das aulas + Check Points 1 e 2 (94 testes)
└── securaPy_platform/       2º semestre: GS final = a plataforma completa (69 testes)  ← projeto principal
```

Regra de ouro: **`GS_1Semestre` é a fonte do núcleo** (coletor, regras, detector…). A plataforma tem uma **cópia
evoluída** em `securaPy_platform/core/` (precisa estar dentro da imagem Docker). Os exercícios de `GS_2Semestre`,
ao contrário, **importam** de `GS_1Semestre` via `comum.py`. Não duplique lógica nova em dois lugares sem motivo.

## 2. securaPy_platform — arquitetura (o que mais importa)

Camadas (cada pasta é um pacote Python; imports são absolutos a partir da raiz de `securaPy_platform/`):

```
core/       NÚCLEO do 1º sem: coletor.py, regras.py, detector.py, enriquecimento.py, integridade.py
db/         mongo_repo.py  (eventos/alertas → MongoDB)      mysql_repo.py (usuários/permissões → MySQL)
ml/         features.py → dados_treino.py → treinar.py → classificar.py ; anomalias.py (Isolation Forest)
ia/         assistente.py  (LLM/mock + regras de fallback + defesa contra prompt injection)
api/        app.py (fábrica create_app, rotas /api/*, validação, handlers de erro)
            auth.py (JWT HS256)   seguranca.py (headers, log de acesso, LimiteTentativas, configurar_logging)
web/        rotas.py (Blueprint "web": dashboard Jinja2), templates/, static/style.css
alertas/    servidor_alertas.py / cliente_alertas.py (TCP, porta 9999; roda em THREAD dentro da API)
servicos/   analise.py (classe Plataforma = orquestração)   bootstrap.py (monta tudo a partir de Settings)
scripts/    gerar_env.py · ingestao.py · verificar_docker.py · demo_e2e.py
settings.py (dataclass Settings.from_env + carregar_env + carregar_blacklist)     wsgi.py (gunicorn wsgi:app)
```

### Fluxo principal — `POST /api/analisar` → `Plataforma._analisar` (`servicos/analise.py`)

```
coletor.carregar_todos_os_logs(pasta)           # pasta restrita a settings.pasta_logs (anti path traversal)
 → regras.aplicar_regras(eventos, regras.json)  # alertas por regra (R001…R005)
 → detector: brute_force, brute_force_temporal, port_scan, verificar_blacklist → gerar_resumo_ameacas
 → ml.features.extrair_features(eventos, blacklist)  → Classificador.pontuar()  # score de risco por IP
 → ml.anomalias.detectar_anomalias()
 → MongoRepo.salvar_eventos / salvar_alertas     # idempotente por "lote" (reanalisar NÃO duplica)
 → alertas CRITICA → plataforma._transmitir → servidor_alertas.broadcast_alerta (consoles TCP)
 → devolve resumo JSON
```

`Plataforma` é o **único ponto de composição**: API e dashboard só falam com ela (`current_app.config["PLATAFORMA"]`).
Dependências são injetadas no construtor (`mongo, usuarios, classificador, assistente, blacklist, transmitir,
consultar_geo`) — é assim que os testes trocam rede/LLM por stubs. Mantenha esse padrão.

### Contratos de dados (a "cola" entre módulos — não mude sem atualizar todos)

- **Evento**: `{timestamp:"AAAA-MM-DD HH:MM:SS", fonte:"auth|firewall|web", tipo, ip, detalhes:"k=v k=v", linha_original}`.
  No Mongo `timestamp` vira `datetime` e ganha `lote`; `serializar()` devolve string e troca `_id`→`id`.
- **Alerta**: `{timestamp, regra_id, regra_nome, severidade, ip, descricao}` (+ `origem`, `lote`, `criado_em` no Mongo).
  Severidades: `INFO < BAIXA < MEDIA < ALTA < CRITICA` (**sem acento**; `normalizar_severidade()` aceita minúsculas/acentos).
- **Features por IP** (ordem fixa em `ml.features.FEATURES`): `n_fail, portas_distintas, em_blacklist, web_erros, total_eventos`.
  A MESMA função alimenta treino e classificação — se mudar `FEATURES`, **retreine** (`python -m ml.treinar`).
- **Rótulos do assistente**: `NORMAL | SUSPEITO | CRITICO` (sem acento, diferente de `CRITICA` de severidade).

### Decisões de projeto que NÃO devem ser desfeitas

1. **Segredos só no ambiente.** Nada de senha/chave no código (o CP2 desconta nota por isso). `Settings.from_env()`
   exige `JWT_SECRET`, `SECRET_KEY`, `MYSQL_PASSWORD`. `.env` está no `.gitignore`; `.env.example` lista as chaves.
2. **Toda query SQL é parametrizada (`%s`).** Nome de coluna/direção em `ORDER BY` só por whitelist (ver CP2 ex. 5).
3. **Sem `|safe` nos templates**; todo POST web tem CSRF; headers `X-Content-Type-Options`, `X-Frame-Options`,
   `Content-Security-Policy: default-src 'self'` em **toda** resposta (`registrar_seguranca`). Como a CSP bloqueia
   inline, **não use `<script>` nem `style=` inline** — use `static/style.css`.
4. **Mensagens de erro genéricas**: 401 igual para "usuário não existe" e "senha errada"; 500 sempre
   `{"erro":"erro interno"}` (detalhe só no log); dependência fora → 503. Entrada inválida → **400, nunca 500**.
5. **Modelo de ML só é carregado após conferir o SHA-256** (`ml.classificar.carregar_modelo`), por causa do `pickle`.
6. **LLM nunca rebaixa o veredito das regras** (`ia/assistente.py`): `max(llm, regras)`; entrada redigida,
   delimitada em `<log>…</log>` e truncada; saída validada por regex; sem `OPENAI_API_KEY` → regras/mock.
7. **JWT**: algoritmo fixo `HS256`, `exp/iat/iss/sub` exigidos (`api/auth.py`). Escrita exige token; leitura é pública
   por padrão (exigência do enunciado) e `EXIGIR_AUTH_LEITURA=1` a protege.
8. Estado em memória (limitador de login, cache de geo, servidor de alertas) ⇒ **um único worker** do gunicorn
   (`--workers 1 --threads 8`). Escalar exige externalizar (Redis).

## 3. Configuração (variáveis de ambiente)

`settings.py` carrega `securaPy_platform/.env` sem sobrescrever variáveis já definidas. Principais:
`MONGO_URI`, `MONGO_DB`, `MYSQL_HOST/PORT/USER/PASSWORD/DATABASE`, `JWT_SECRET`, `SECRET_KEY` (≥16 chars),
`ADMIN_EMAIL`/`ADMIN_PASSWORD` (cria o 1º operador nível 5 se a tabela estiver vazia), `ALERTAS_ATIVO`,
`ALERTAS_PORTA` (9999), `LOGS_DIR`, `EXIGIR_AUTH_LEITURA`, `COOKIE_SEGURO`, `OPENAI_API_KEY` (opcional).
`python scripts/gerar_env.py` cria um `.env` com segredos aleatórios (não sobrescreve).

## 4. Como rodar

```bash
# Plataforma completa (API + MongoDB + MySQL), na pasta securaPy_platform/
python scripts/gerar_env.py
docker compose up -d --build
python scripts/verificar_docker.py http://127.0.0.1:5000     # 3 contêineres running?
python scripts/demo_e2e.py                                   # login → análise → 2 consoles → IP → relatório
docker compose down                                          # (-v apaga volumes)
```

Dashboard `http://127.0.0.1:5000` (login = `ADMIN_*` do `.env`). Os bancos **não publicam portas** no host.
A imagem **treina o modelo no build** (`RUN python -m ml.treinar`) — `ml/modelo.pkl` do Git é só entregável e é
ignorado pelo `.dockerignore`. Console de alertas: `python alertas/cliente_alertas.py`.

## 5. Testes

```bash
cd securaPy_platform && python -m pytest testes -q     # 69 testes
cd GS_2Semestre      && python -m pytest testes -q     # 94 testes
cd GS_1Semestre/securaPy && python -m pytest testes/ -q  # 197 testes (1º sem)
```

- Usam **MongoDB/MySQL reais** se acessíveis; sem Mongo caem para `mongomock`; sem MySQL os testes de MySQL são **pulados**
  (um resultado "N passed, M skipped" quase sempre significa banco fora do ar — confira antes de confiar).
- Laboratório de bancos: `GS_2Semestre/docker-compose.yml` (containers `mongo-lab` 27017 e `mysql-lab` 3306).
  Testes da plataforma usam o banco `teste_plataforma`; os de `GS_2Semestre`, `teste_gs2`. Senha do MySQL de teste:
  `TEST_MYSQL_PASSWORD` ou `GS_2Semestre/.env`.
- Mapa teste ↔ enunciado: `test_modulo_a_core` (A1–A4), `test_modulo_b_c_db_ml` (B, C), `test_modulo_d_api` (D),
  `test_modulo_e_web` (E), `test_modulo_g_f_alertas_docker` (G, alertas, F). Cenários por ID estão no README da plataforma.
- Ao alterar comportamento público (rota, contrato, mensagem de erro), atualize o teste correspondente e o README.

## 6. GS_2Semestre (exercícios)

Um arquivo por exercício (`aulaNN/exN_M_*.py`, `checkpoints/cp1/exNN_*.py`, `checkpoints/cp2/exNN_*.py`).
Padrão: funções puras recebem a conexão/coleção por parâmetro (testáveis) e `if __name__ == "__main__"` faz a demo.
Apps Flask usam `create_app(...)` com dependências injetáveis. `comum.py` expõe `LOGS_DIR`, adiciona o código do
1º semestre ao `sys.path`, lê `GS_2Semestre/.env` e fornece `get_mongo_db()/get_mysql(database, criar)`.
`checkpoints/cp2/ex10/` contém um app **propositalmente vulnerável** (`app_vulneravel.py`) — nunca o execute com
`python app_vulneravel.py` (liga em `0.0.0.0` com debug); use `flask --app app_vulneravel run --debug --no-reload --port 5001`.
`exploit.py` recusa qualquer host que não seja local — mantenha essa trava.

## 7. Armadilhas já encontradas (economize tempo)

- **`mysql.connector` + coleta de lixo:** `db().cursor()` sem guardar a conexão fecha-a antes do `execute`
  ("Cursor is not connected"). Sempre `con = ...; cur = con.cursor()` e feche em `finally`.
- **Saída acentuada no Windows:** rode Python com `PYTHONIOENCODING=utf-8` ao capturar saída em pipe.
- **Docker Desktop no Windows para sozinho**, derrubando os containers (`mongo-lab`/`mysql-lab` ficam `Exited`);
  `docker compose up -d` na pasta do lab os religa — espere o MySQL responder ao `mysqladmin ping` antes de testar.
- **Dados reais dos logs:** `auth.log` tem **11** FAILs de `185.220.101.1` (os enunciados dizem 10); a severidade
  de brute force para esse IP é `ALTA`. Os testes refletem os valores reais.
- **Dataset de ML é sintético** (`ml/dados_treino.py`, seed fixa); as métricas medem o gerador, não tráfego real.
  O `.pkl` depende da versão do scikit-learn/Python — por isso o Docker retreina no build.
- **mongomock** emite `DeprecationWarning` de `utcnow()`; é inofensivo. Ele não substitui o Mongo real em tudo
  (use o real para validar agregações novas).
- **IsolationForest com poucos pontos é instável:** `ml/anomalias.py` e o CP2 ex. 9 exigem população mínima (6 IPs)
  e pisos absolutos para não bloquear usuário legítimo.
- Avisos `LF will be replaced by CRLF` do Git no Windows são inofensivos.

## 8. Convenções para modificar

- Português, `snake_case`, docstrings curtas explicando o **porquê** (segurança/decisão), não o óbvio.
- Funções com responsabilidade única; I/O (rede, banco, LLM, relógio) injetado ⇒ fácil de simular nos testes.
- Estruturas de dados: `set` para blacklist/portas, `dict` para contagens, tuplas para pares imutáveis.
- Erros esperados viram exceções de domínio (`UsuarioDuplicado`, `RepositorioIndisponivel`, `ModeloAdulterado`…),
  traduzidas para HTTP **em um só lugar** (`registrar_erros` em `api/app.py`). Rotas web usam `erro.html`.
- Nova rota de API: validar com `Invalido` (→400), proteger com `@exigir_token(nivel)` se escrever,
  paginar com `paginacao()` (teto 100), registrar o teste, e documentar na tabela do README da plataforma.
- Nunca commitar `.env`, `saida/*` (exceto `relatorio_exemplo.json`), `__pycache__`.
- Commits e push só quando o usuário pedir. O repositório remoto é `pedroross1z/securaPy` (branch `main`).

## 9. Pendências conhecidas (fora do código)

- `securaPy_platform/README.md`: grupo precisa preencher integrantes/RMs/divisão de tarefas.
- Vídeo de apresentação (12–18 min) — a gravar pelo grupo.
- Nada foi testado contra a API real da OpenAI (só mock/regras).
- Não existe `cp3_2semestre.md` no repositório do professor.
