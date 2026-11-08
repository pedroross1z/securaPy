"""Exercicio 7.3 - API de usuarios com Flask + MySQL e tratamento de erros.

Status: 201 criado | 400 corpo invalido | 404 inexistente | 409 email duplicado
        500 falha de banco ("servico indisponivel": sem traceback, sem query)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from comum import get_mysql  # noqa: E402

import mysql.connector  # noqa: E402
from flask import Flask, jsonify, request  # noqa: E402


def validar(dados, parcial=False):
    if not isinstance(dados, dict):
        return "corpo JSON obrigatório"
    if not parcial and ("nome" not in dados or "email" not in dados):
        return "nome e email obrigatórios"
    for campo in ("nome", "email"):
        if campo in dados and (not isinstance(dados[campo], str) or not dados[campo].strip()):
            return f"{campo} inválido"
    if "email" in dados and "@" not in dados["email"]:
        return "email inválido"
    n = dados.get("nivel_acesso", 1)
    if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= 5:
        return "nivel_acesso deve ser inteiro de 1 a 5"
    return None


def create_app(conexao_factory=get_mysql):
    app = Flask(__name__)

    def executar(sql, params=(), consulta=None):
        """Roda UMA query parametrizada; fecha a conexao sempre.

        consulta: None (escrita) | 'um' | 'todos'. Retorna (resultado, cursor.rowcount, lastrowid).
        """
        conn = conexao_factory()
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute(sql, params)
            resultado = None
            if consulta == "um":
                resultado = cur.fetchone()
            elif consulta == "todos":
                resultado = cur.fetchall()
            else:
                conn.commit()
            return resultado, cur.rowcount, cur.lastrowid
        finally:
            conn.close()

    @app.errorhandler(mysql.connector.IntegrityError)
    def duplicado(e):
        return jsonify({"erro": "email já cadastrado"}), 409

    @app.errorhandler(mysql.connector.Error)
    def falha_banco(e):
        app.logger.error("Falha de banco: %s", e)          # detalhe so no log do servidor
        return jsonify({"erro": "serviço indisponível"}), 500

    @app.errorhandler(404)
    def rota_inexistente(e):
        return jsonify({"erro": "Rota não existe"}), 404

    @app.errorhandler(500)
    def erro_interno(e):
        return jsonify({"erro": "Erro interno do servidor"}), 500

    @app.get("/api/usuarios")
    def listar():
        linhas, _, _ = executar(
            "SELECT id, nome, email, nivel_acesso FROM usuarios ORDER BY id", consulta="todos")
        return jsonify(linhas)

    @app.get("/api/usuarios/<int:id>")
    def obter(id):
        u, _, _ = executar(
            "SELECT id, nome, email, nivel_acesso FROM usuarios WHERE id = %s", (id,), "um")
        if not u:
            return jsonify({"erro": "usuário não encontrado"}), 404
        return jsonify(u)

    @app.post("/api/usuarios")
    def criar():
        dados = request.get_json(silent=True)
        erro = validar(dados)
        if erro:
            return jsonify({"erro": erro}), 400
        _, _, novo_id = executar(
            "INSERT INTO usuarios (nome, email, nivel_acesso) VALUES (%s, %s, %s)",
            (dados["nome"], dados["email"], dados.get("nivel_acesso", 1)))
        return jsonify({"id": novo_id}), 201

    @app.put("/api/usuarios/<int:id>")
    def atualizar(id):
        dados = request.get_json(silent=True)
        erro = validar(dados, parcial=True)
        if erro:
            return jsonify({"erro": erro}), 400
        campos = [c for c in ("nome", "email", "nivel_acesso") if c in dados]
        if not campos:
            return jsonify({"erro": "nenhum campo para atualizar"}), 400
        # nomes de coluna vem de uma whitelist fixa; valores seguem parametrizados
        sql = "UPDATE usuarios SET " + ", ".join(f"{c} = %s" for c in campos) + " WHERE id = %s"
        _, _, _ = executar(sql, tuple(dados[c] for c in campos) + (id,))
        existe, _, _ = executar("SELECT id FROM usuarios WHERE id = %s", (id,), "um")
        if not existe:
            return jsonify({"erro": "usuário não encontrado"}), 404
        return jsonify({"mensagem": "Atualizado"})

    @app.delete("/api/usuarios/<int:id>")
    def remover(id):
        _, afetadas, _ = executar("DELETE FROM usuarios WHERE id = %s", (id,))
        if afetadas == 0:
            return jsonify({"erro": "usuário não encontrado"}), 404
        return jsonify({"mensagem": "Removido"})

    return app


def garantir_tabela(conexao_factory=get_mysql):
    conn = conexao_factory()
    try:
        conn.cursor().execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nome VARCHAR(100) NOT NULL,
                email VARCHAR(150) NOT NULL UNIQUE,
                nivel_acesso INT NOT NULL DEFAULT 1,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""")
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    garantir_tabela()
    create_app().run(port=5000, debug=False)
