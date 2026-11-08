# Exercício 8.3 — Auditoria de código: as 5 falhas

Código auditado (propositalmente inseguro):

```python
@app.route("/user/<nome>")
def user(nome):
    cur.execute("SELECT * FROM users WHERE nome='" + nome + "'")   # (1)
    dados = cur.fetchone()
    return f"<h1>Bem-vindo {nome}</h1>" + str(dados)               # (2)

app.run(debug=True, host="0.0.0.0")                                # (3)
SENHA_DB = "123456"                                                # (4)
# (5) nenhuma rota registra logs de acesso ou tentativa de erro
```

## Resumo

| # | Falha | OWASP Top 10:2025 | Gravidade | Correção |
|---|-------|-------------------|-----------|----------|
| 1 | SQL Injection por concatenação | **A05 – Injection** | Crítica | Query parametrizada |
| 2 | XSS refletido (`nome` ecoado sem escape) | **A05 – Injection** | Alta | Escapar a saída / Jinja2 |
| 3 | `debug=True` + `host="0.0.0.0"` | **A02 – Security Misconfiguration** | Crítica | `debug=False`, WSGI, `127.0.0.1`/proxy |
| 4 | Segredo e senha fraca no código-fonte | **A04 – Cryptographic Failures** / A02 | Alta | Variável de ambiente + senha forte, usuário de menor privilégio |
| 5 | Nenhum log de acesso/erro | **A09 – Security Logging & Alerting Failures** | Média | `logging` de acessos, falhas e entradas suspeitas |

## Detalhamento

### 1. SQL Injection — A05
- **Problema:** `"... WHERE nome='" + nome + "'"` mistura entrada do usuário com código SQL.
  Acessar `/user/' OR '1'='1` retorna **todas** as linhas; `/user/'; DROP TABLE users;--`
  tenta executar comandos adicionais (dependendo do driver/permissões).
- **Impacto:** vazamento total da tabela, bypass de autenticação, alteração/destruição de dados.
- **Correção:** o driver envia a entrada separada da query, sempre como dado:
  ```python
  cur.execute("SELECT id, nome FROM users WHERE nome = %s", (nome,))
  ```
  Além disso, selecione só as colunas necessárias (nada de `SELECT *` com hash de senha).

### 2. XSS refletido — A05
- **Problema:** `f"<h1>Bem-vindo {nome}</h1>"` devolve a entrada crua. `/user/<script>alert(1)</script>`
  executa JavaScript no navegador da vítima. `str(dados)` também ecoa dados do banco sem escape
  (XSS armazenado se algum campo contiver HTML).
- **Correção:** validar a entrada e **escapar a saída** (Jinja2 já faz isso):
  ```python
  from markupsafe import escape
  return f"<h1>Bem-vindo {escape(nome)}</h1>"
  # ou: render_template_string("<h1>Bem-vindo {{ nome }}</h1>", nome=nome)
  ```
  Complemento: header `Content-Security-Policy: default-src 'self'`.

### 3. Security Misconfiguration — A02
- **Problema:** `debug=True` expõe o **depurador interativo do Werkzeug** (execução de código
  pelo navegador) e stack traces; `host="0.0.0.0"` publica o serviço em todas as interfaces.
  A combinação é equivalente a entregar um shell remoto.
- **Correção:** `debug=False` (ou nem chamar `app.run` em produção), servir via WSGI
  (`gunicorn`/`waitress`) atrás de proxy reverso com TLS, e escutar em `127.0.0.1`
  quando não houver necessidade de exposição direta.

### 4. Segredo no código e senha fraca — A04 / A02
- **Problema:** `SENHA_DB = "123456"` vai para o Git, para backups e para qualquer pessoa com
  acesso ao repositório; além disso é uma senha trivial (está em qualquer dicionário).
- **Correção:**
  ```python
  import os
  SENHA_DB = os.environ["DB_PASSWORD"]      # falha cedo se não estiver definida
  ```
  Use senha longa/aleatória, gerenciador de segredos (Vault, KMS, secrets do orquestrador),
  usuário de banco com privilégios mínimos (só `SELECT` nesta tabela) e rotacione a credencial
  que já vazou.

### 5. Ausência de logging — A09
- **Problema:** sem logs não há como detectar o ataque dos itens 1 e 2, nem investigar depois.
  É exatamente o problema que o SecuraPy resolve.
- **Correção:** registrar acessos, falhas e entradas suspeitas — sem gravar senhas/PII:
  ```python
  import logging
  logging.basicConfig(filename="app.log", level=logging.INFO,
                      format="%(asctime)s %(levelname)s %(message)s")

  @app.route("/user/<nome>")
  def user(nome):
      logging.info("GET /user ip=%s nome=%r", request.remote_addr, nome[:50])
      ...
      except mysql.connector.Error:
          logging.exception("erro de banco em /user")
          return jsonify({"erro": "serviço indisponível"}), 500
  ```
  O arquivo gerado pode ser lido pelo `coletor.py` do SecuraPy e analisado pelo motor de regras.

## Versão corrigida

```python
import logging, os
import mysql.connector
from flask import Flask, abort, request
from markupsafe import escape

app = Flask(__name__)
logging.basicConfig(filename="app.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

def get_db():
    return mysql.connector.connect(
        host=os.environ.get("DB_HOST", "localhost"), user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"], database=os.environ["DB_NAME"])

@app.route("/user/<nome>")
def user(nome):
    logging.info("GET /user ip=%s nome=%r", request.remote_addr, nome[:50])
    conn = get_db()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, nome FROM users WHERE nome = %s", (nome,))   # (1)
        dados = cur.fetchone()
    except mysql.connector.Error:
        logging.exception("erro de banco em /user")                          # (5)
        abort(500)
    finally:
        conn.close()
    if not dados:
        abort(404)
    return f"<h1>Bem-vindo {escape(dados['nome'])}</h1>"                     # (2)

if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1")                                   # (3)
```
