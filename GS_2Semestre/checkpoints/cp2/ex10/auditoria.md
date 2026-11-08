# CP2 – Exercício 10: auditoria de `app_vulneravel.py`

Uma linha por falha (OWASP Top 10:2025). As linhas marcadas **AUSÊNCIA** não estão escritas em lugar
nenhum do arquivo — a falha é justamente o que *falta*.

| # | Falha | OWASP 2025 | Impacto | Correção (em `app_seguro.py`) |
|---|-------|-----------|---------|-------------------------------|
| 1 | `f"... LIKE '%{nome}%'"` concatena a entrada na query (SQL Injection) | **A05 – Injection** | Leitura de toda a tabela (`' OR '1'='1`), possível escrita/destruição conforme o privilégio da conta | Query parametrizada: `LIKE %s` com `%` e `_` escapados (+ `LIMIT 100`) |
| 2 | `/perfil` devolve `u` dentro de HTML sem escape (XSS refletido) | **A05 – Injection** | JavaScript no navegador da vítima: roubo de sessão, defacement | `markupsafe.escape()` / Jinja2 + CSP |
| 3 | **AUSÊNCIA** de autenticação **e** autorização no `DELETE /api/usuarios/<id>` | **A01 – Broken Access Control** (+ A07) | Qualquer anônimo apaga qualquer usuário (IDOR/função administrativa exposta) | Token `Bearer` obrigatório (401), nível ≥ 5 (403), comparação em tempo constante |
| 4 | `/api/relatorio` falha e `debug=True` devolve traceback, query e nome de tabela | **A10 – Mishandling of Exceptional Conditions** (+ A02) | Mapa do banco para o atacante; o depurador do Werkzeug ainda permite execução de código | `errorhandler` genérico → `500 {"erro":"erro interno"}`; detalhe só no log |
| 5 | `SELECT *` devolve a coluna `senha` (hash) na resposta | **A04 – Cryptographic Failures** (+ A01) | Exposição excessiva de dados: hashes vazam e podem ser quebrados offline | Selecionar apenas `id, nome, email` |
| 6 | **AUSÊNCIA** de headers de segurança (`X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`) | **A02 – Security Misconfiguration** | Clickjacking, MIME sniffing, XSS sem camada de defesa extra | `after_request` com os 3 headers |
| 7 | `app.run(debug=True, host="0.0.0.0")` | **A02 – Security Misconfiguration** | Console interativo exposto a toda a rede = execução remota de código | `debug=False`, `127.0.0.1` e servidor WSGI atrás de proxy |
| 8 | `SENHA_MESTRA` e senha do banco escritas no código (e `root` como usuário) | **A04 / A02** | Segredo vai para o Git, backups e logs; conta root excede o privilégio necessário | Segredos em variáveis de ambiente; usuário de banco com privilégio mínimo; rotacionar o que vazou |
| 9 | **AUSÊNCIA** de logging/alerta (nenhum acesso, falha ou DELETE é registrado) | **A09 – Security Logging & Alerting Failures** | Nenhuma das falhas acima seria detectada nem investigada | `logging` de cada requisição (IP, método, rota, status, tempo) e de ações sensíveis |
| 10 | `db()` abre uma conexão por requisição e **nunca fecha** | **A10 / A06** | Esgotamento de conexões → negação de serviço trivial | `try/finally: con.close()` (ou pool) |
| 11 | Sem limite de resultados nem de taxa de requisições | **A06 – Insecure Design** | Extração em massa e abuso da API | `LIMIT` fixo; rate limiting (ver CP2 – Exercício 9) |

## Provas

Ambos os cenários usam o **mesmo** `exploit.py` (somente contra `127.0.0.1`):

```
# python exploit.py http://127.0.0.1:5001   (app_vulneravel.py)
=== 6 de 6 ataques bem-sucedidos ===

# python exploit.py http://127.0.0.1:5002   (app_seguro.py)
=== 0 de 6 ataques bem-sucedidos ===
```

Os itens 7–11 não são exploráveis de forma limpa por requisição HTTP; foram corrigidos e justificados
acima. O item 8 (segredo hard-coded) é verificável por leitura do código (`grep`).

> Observação: no código do enunciado, `db().cursor()` deixa a conexão sem referência e o coletor de lixo a
> fecha antes do `execute` (erro "Cursor is not connected" com o driver puro-Python). A cópia de laboratório
> usa `con = db(); cur = con.cursor()` para que a falha real (conexão nunca fechada) seja exercitável.
