"""Exercicio 6.3 - GET /api/checar-ip/<ip>: blacklist + privado/publico.

Reaproveita eh_ip_privado() do enriquecimento.py do SecuraPy (1o semestre).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import comum  # noqa: E402,F401  (publica os modulos do SecuraPy no sys.path)

from enriquecimento import eh_ip_privado  # noqa: E402
from flask import Flask, jsonify  # noqa: E402

BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172"}


def ip_valido(ip):
    partes = ip.split(".")
    return (len(partes) == 4
            and all(p.isdigit() and len(p) <= 3 and 0 <= int(p) <= 255 for p in partes))


def create_app(blacklist=None):
    app = Flask(__name__)
    lista = BLACKLIST if blacklist is None else blacklist

    @app.get("/api/checar-ip/<ip>")
    def checar(ip):
        if not ip_valido(ip):
            return jsonify({"erro": "IP inválido"}), 400
        return jsonify({
            "ip": ip,
            "na_blacklist": ip in lista,
            "tipo": "privado" if eh_ip_privado(ip) else "publico",
        })

    return app


if __name__ == "__main__":
    create_app().run(port=5000, debug=False)
