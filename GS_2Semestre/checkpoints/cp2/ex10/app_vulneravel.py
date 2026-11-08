# ===== app_vulneravel.py — LABORATORIO APENAS =====
# Código do enunciado, mantido com TODAS as falhas. Única mudança: a senha do banco vem
# do ambiente (para não gravar a senha do laboratório no repositório); a SENHA_MESTRA
# hard-coded do enunciado continua aqui de propósito (é uma das falhas auditadas).
# Segunda mudança: `con = db(); cur = con.cursor()` no lugar de `db().cursor()`. No original a
# conexão fica sem referência e o coletor de lixo a fecha antes do execute ("Cursor is not
# connected" com o driver puro-Python); guardar a variável preserva a falha real: a conexão
# nunca é fechada (vazamento de conexões).
#
# Rodar (liga em 127.0.0.1; NÃO use `python app_vulneravel.py`, que escutaria em 0.0.0.0):
#   flask --app app_vulneravel run --debug --no-reload --port 5001
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import comum  # noqa: E402,F401  (carrega o .env)

from flask import Flask, request, jsonify  # noqa: E402
import mysql.connector  # noqa: E402

app = Flask(__name__)
SENHA_MESTRA = "Cyber@2024"


def db():
    return mysql.connector.connect(host=os.environ.get("MYSQL_HOST", "localhost"), user="root",
                                   password=os.environ["MYSQL_PASSWORD"], database=os.environ.get("CP2_DATABASE", "cp2"))


@app.route("/api/usuarios/buscar")
def buscar():
    nome = request.args.get("nome", "")
    con = db(); cur = con.cursor(dictionary=True)
    cur.execute(f"SELECT * FROM usuarios WHERE nome LIKE '%{nome}%'")
    return jsonify(cur.fetchall())


@app.route("/perfil")
def perfil():
    return f"<h1>Bem-vindo, {request.args.get('u','')}</h1>"


@app.route("/api/usuarios/<int:uid>", methods=["DELETE"])
def remover(uid):
    con = db(); cur = con.cursor()
    cur.execute("DELETE FROM usuarios WHERE id = %s", (uid,))
    con.commit()
    return jsonify({"removido": uid})


@app.route("/api/relatorio")
def relatorio():
    con = db(); cur = con.cursor()
    cur.execute("SELECT * FROM tabela_inexistente")
    return jsonify(cur.fetchall())


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
