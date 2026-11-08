"""Exercicio 8.2 - POST /login endurecido (MySQL + query parametrizada).

Controles implementados
  * campos vazios            -> 400
  * credencial errada        -> 401 com MENSAGEM GENERICA (mesma p/ usuario inexistente e senha errada)
  * limite de tentativas     -> 429 apos MAX_FALHAS falhas na janela (por IP + usuario)
  * senhas guardadas como hash (scrypt/pbkdf2 do werkzeug), nunca em texto puro
  * hash "falso" comparado quando o usuario nao existe -> tempo de resposta parecido
    (evita enumeracao de usuarios por timing)
  * log de falhas (A09) sem registrar a senha

Por que a mensagem e generica? Se a API dissesse "usuario nao existe" ou "senha
incorreta", um atacante poderia testar uma lista de nomes e descobrir quais contas
existem (user enumeration, OWASP A07) para depois focar o brute force nelas.
"""
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from comum import get_mysql  # noqa: E402

from flask import Flask, jsonify, request  # noqa: E402
from werkzeug.security import check_password_hash, generate_password_hash  # noqa: E402

MAX_FALHAS = 5
JANELA_SEGUNDOS = 300
HASH_FALSO = generate_password_hash("senha-inexistente-para-igualar-tempo")

log = logging.getLogger("login")


def semear(conexao, usuarios=None):
    """Cria a tabela contas_login e grava os usuarios de laboratorio (com hash)."""
    usuarios = usuarios or {"admin": "Cyber@2024", "analista": "S3gur4nca!"}
    cur = conexao.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS contas_login (
                       usuario VARCHAR(50) PRIMARY KEY,
                       senha_hash VARCHAR(255) NOT NULL)""")
    for usuario, senha in usuarios.items():
        cur.execute("REPLACE INTO contas_login (usuario, senha_hash) VALUES (%s, %s)",
                    (usuario, generate_password_hash(senha)))
    conexao.commit()


def buscar_hash_mysql(usuario):
    conn = get_mysql()
    try:
        cur = conn.cursor()
        cur.execute("SELECT senha_hash FROM contas_login WHERE usuario = %s", (usuario,))
        linha = cur.fetchone()
        return linha[0] if linha else None
    finally:
        conn.close()


def create_app(buscar_hash=buscar_hash_mysql, relogio=time.monotonic):
    app = Flask(__name__)
    falhas = {}          # (ip, usuario) -> [instantes das falhas recentes]

    def falhas_recentes(chave):
        agora = relogio()
        recentes = [t for t in falhas.get(chave, []) if agora - t < JANELA_SEGUNDOS]
        falhas[chave] = recentes
        return recentes

    @app.post("/login")
    def login():
        dados = request.get_json(silent=True)
        if not isinstance(dados, dict):
            return jsonify({"erro": "usuario e senha obrigatórios"}), 400
        usuario, senha = dados.get("usuario"), dados.get("senha")
        if not isinstance(usuario, str) or not isinstance(senha, str) or not usuario or not senha:
            return jsonify({"erro": "usuario e senha obrigatórios"}), 400

        chave = (request.remote_addr, usuario)
        if len(falhas_recentes(chave)) >= MAX_FALHAS:
            return jsonify({"erro": "Muitas tentativas. Tente novamente mais tarde."}), 429

        hash_salvo = buscar_hash(usuario)
        senha_ok = check_password_hash(hash_salvo or HASH_FALSO, senha)
        if hash_salvo is None or not senha_ok:
            falhas[chave].append(relogio())
            log.warning("login falhou usuario=%r ip=%s", usuario, request.remote_addr)
            return jsonify({"erro": "Credenciais inválidas"}), 401

        falhas.pop(chave, None)
        return jsonify({"mensagem": "Login OK"}), 200

    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    c = get_mysql()
    semear(c)
    c.close()
    create_app().run(port=5000, debug=False)
