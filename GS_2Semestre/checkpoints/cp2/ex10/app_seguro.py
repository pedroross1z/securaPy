"""app_seguro.py - versao corrigida de app_vulneravel.py (ver auditoria.md).

Rodar:  flask --app app_seguro run --no-reload --port 5002
Variaveis de ambiente: MYSQL_PASSWORD, ADMIN_TOKEN (nivel 5), BAIXO_TOKEN (nivel 1).
"""
import hmac
import logging
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import comum  # noqa: E402  (carrega o .env)

import mysql.connector  # noqa: E402
from flask import Flask, g, jsonify, request  # noqa: E402
from markupsafe import escape  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("app_seguro")

app = Flask(__name__)
NIVEL_ADMIN = 5


def db():
    return mysql.connector.connect(host=os.environ.get("MYSQL_HOST", "localhost"), user="root",
                                   password=os.environ["MYSQL_PASSWORD"], database=os.environ.get("CP2_DATABASE", "cp2"))


def _nivel_do_token(token):
    """Compara em tempo constante com os tokens vindos do ambiente (nada hard-coded)."""
    for var, nivel in (("ADMIN_TOKEN", 5), ("BAIXO_TOKEN", 1)):
        esperado = os.environ.get(var)
        if esperado and token and hmac.compare_digest(token, esperado):
            return nivel
    return None


def exige_nivel(minimo):
    auth = request.headers.get("Authorization", "")
    nivel = _nivel_do_token(auth[7:] if auth.startswith("Bearer ") else "")
    if nivel is None:
        return jsonify({"erro": "autenticação necessária"}), 401
    if nivel < minimo:
        return jsonify({"erro": "acesso negado"}), 403
    return None


@app.before_request
def inicio():
    g.t0 = time.perf_counter()


@app.after_request
def depois(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    log.info("%s %s %s %s %.1fms", request.remote_addr, request.method, request.full_path.rstrip("?"),
             resp.status_code, (time.perf_counter() - g.t0) * 1000)      # A09: log de acesso
    return resp


@app.route("/api/usuarios/buscar")
def buscar():
    nome = request.args.get("nome", "")[:50]
    curinga = nome.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    con = db()
    try:
        cur = con.cursor(dictionary=True)
        cur.execute("SELECT id, nome, email FROM usuarios WHERE nome LIKE %s LIMIT 100",   # sem coluna senha
                    (f"%{curinga}%",))
        return jsonify(cur.fetchall())
    finally:
        con.close()


@app.route("/perfil")
def perfil():
    return f"<h1>Bem-vindo, {escape(request.args.get('u', '')[:50])}</h1>"


@app.route("/api/usuarios/<int:uid>", methods=["DELETE"])
def remover(uid):
    negado = exige_nivel(NIVEL_ADMIN)
    if negado:
        return negado
    con = db()
    try:
        cur = con.cursor()
        cur.execute("DELETE FROM usuarios WHERE id = %s", (uid,))
        con.commit()
        if cur.rowcount == 0:
            return jsonify({"erro": "não encontrado"}), 404
    finally:
        con.close()
    log.warning("usuario %s removido por %s", uid, request.remote_addr)
    return jsonify({"removido": uid})


@app.route("/api/relatorio")
def relatorio():
    con = db()
    try:
        cur = con.cursor()
        cur.execute("SELECT * FROM tabela_inexistente")
        return jsonify(cur.fetchall())
    finally:
        con.close()


@app.errorhandler(Exception)
def erro(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return jsonify({"erro": e.name}), e.code
    log.exception("erro nao tratado em %s", request.path)       # detalhe so no log do servidor
    return jsonify({"erro": "erro interno"}), 500


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5002)
