"""Exercicio 6.1 - API CRUD de usuarios (em memoria)."""
from flask import Flask, jsonify, request

NIVEIS = range(1, 6)


def create_app():
    app = Flask(__name__)
    usuarios = []
    estado = {"proximo_id": 1}

    def achar(id):
        return next((u for u in usuarios if u["id"] == id), None)

    def validar(dados, id_atual=None, parcial=False):
        """Retorna mensagem de erro (str) ou None se estiver tudo certo."""
        if not isinstance(dados, dict):
            return "corpo JSON obrigatório"
        if not parcial:
            faltando = [c for c in ("nome", "email", "nivel") if c not in dados]
            if faltando:
                return f"campos obrigatórios: {', '.join(faltando)}"
        if "nivel" in dados and (not isinstance(dados["nivel"], int)
                                 or isinstance(dados["nivel"], bool)
                                 or dados["nivel"] not in NIVEIS):
            return "nível inválido (use 1 a 5)"
        if "email" in dados:
            if not isinstance(dados["email"], str) or "@" not in dados["email"]:
                return "email inválido"
            if any(u["email"] == dados["email"] and u["id"] != id_atual for u in usuarios):
                return "email já existe"
        return None

    @app.get("/api/usuarios")
    def listar():
        return jsonify(usuarios)

    @app.get("/api/usuarios/<int:id>")
    def obter(id):
        u = achar(id)
        if u is None:
            return jsonify({"erro": "Usuário não encontrado"}), 404
        return jsonify(u)

    @app.post("/api/usuarios")
    def criar():
        dados = request.get_json(silent=True)
        erro = validar(dados)
        if erro:
            return jsonify({"erro": erro}), 400
        u = {"id": estado["proximo_id"], "nome": dados["nome"],
             "email": dados["email"], "nivel": dados["nivel"]}
        usuarios.append(u)
        estado["proximo_id"] += 1
        return jsonify(u), 201

    @app.put("/api/usuarios/<int:id>")
    def atualizar(id):
        u = achar(id)
        if u is None:
            return jsonify({"erro": "Usuário não encontrado"}), 404
        dados = request.get_json(silent=True)
        erro = validar(dados, id_atual=id, parcial=True)
        if erro:
            return jsonify({"erro": erro}), 400
        u.update({k: dados[k] for k in ("nome", "email", "nivel") if k in dados})
        return jsonify(u)

    @app.delete("/api/usuarios/<int:id>")
    def deletar(id):
        u = achar(id)
        if u is None:
            return jsonify({"erro": "Usuário não encontrado"}), 404
        usuarios.remove(u)
        return jsonify({"mensagem": "Removido"}), 200

    @app.errorhandler(404)
    def nao_encontrado(e):
        return jsonify({"erro": "Rota não existe"}), 404

    @app.errorhandler(405)
    def metodo_nao_permitido(e):
        return jsonify({"erro": "Método não permitido"}), 405

    @app.errorhandler(500)
    def erro_interno(e):
        return jsonify({"erro": "Erro interno do servidor"}), 500

    return app


if __name__ == "__main__":
    # debug=False: o console interativo do debug e uma falha grave (Aula 8, A02)
    create_app().run(port=5000, debug=False)
