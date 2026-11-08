"""Exercicio 6.2 - Endpoint POST /api/analisar-senha."""
import re

from flask import Flask, jsonify, request

ESPECIAIS = r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?~`]"


def criterios_senha(senha):
    return {
        "tamanho_min": len(senha) >= 8,
        "maiuscula": bool(re.search(r"[A-Z]", senha)),
        "minuscula": bool(re.search(r"[a-z]", senha)),
        "numero": bool(re.search(r"\d", senha)),
        "especial": bool(re.search(ESPECIAIS, senha)),
    }


def verificar_senha(senha):
    """Classifica a forca pela quantidade de criterios atendidos (0 a 5)."""
    atendidos = sum(criterios_senha(senha).values())
    if atendidos == 5:
        return "Muito forte"
    if atendidos == 4:
        return "Forte"
    if atendidos == 3:
        return "Média"
    return "Fraca"


def create_app():
    app = Flask(__name__)

    @app.post("/api/analisar-senha")
    def analisar():
        dados = request.get_json(silent=True)
        if not isinstance(dados, dict) or "senha" not in dados:
            return jsonify({"erro": "campo 'senha' obrigatório"}), 400
        if not isinstance(dados["senha"], str):
            return jsonify({"erro": "campo 'senha' deve ser texto"}), 400
        senha = dados["senha"]
        # a senha nunca e registrada em log nem devolvida na resposta
        return jsonify({"forca": verificar_senha(senha), "criterios": criterios_senha(senha)})

    return app


if __name__ == "__main__":
    create_app().run(port=5000, debug=False)
