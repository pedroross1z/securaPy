"""CP2 - Exercicio 5: GET /api/eventos?ordenar_por=&ordem=&tamanho=  (ORDER BY com whitelist).

Por que `LIMIT %s` funciona mas `ORDER BY %s` nao?
  - LIMIT recebe um VALOR: o driver o escapa/quota e o banco o trata como dado.
  - ORDER BY recebe um IDENTIFICADOR (nome de coluna): se o placeholder o quotasse
    viraria uma string literal ('criado_em'), que nao ordena nada; e se o concatenarmos,
    o atacante escreve SQL. Identificador nao e dado - so entra por mapa fechado (whitelist).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from comum import get_mysql  # noqa: E402

from flask import Flask, jsonify, request  # noqa: E402

COLUNAS = {"data": "criado_em", "sev": "severidade", "ip": "ip_origem"}
ORDEM = {"asc": "ASC", "desc": "DESC"}
TAMANHO_PADRAO, TAMANHO_MAXIMO = 20, 100

EVENTOS = [
    ("185.220.101.1", "critica", "BRUTE_FORCE"), ("185.220.101.1", "alta", "PORT_SCAN"),
    ("91.240.118.172", "alta", "PATH_TRAVERSAL"), ("45.33.32.156", "media", "XSS"),
    ("192.168.1.10", "baixa", "LOGIN_OK"), ("91.240.118.172", "media", "RECON"),
    ("45.33.32.156", "critica", "SQLI"), ("10.0.0.5", "baixa", "LOGIN_OK"),
]


def preparar(con):
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS eventos")
    cur.execute("""CREATE TABLE eventos (
        id INT AUTO_INCREMENT PRIMARY KEY, ip_origem VARCHAR(45),
        severidade ENUM('baixa','media','alta','critica'), tipo VARCHAR(50),
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    cur.executemany("INSERT INTO eventos (ip_origem, severidade, tipo) VALUES (%s, %s, %s)", EVENTOS)
    con.commit()


def create_app(conexao_factory=lambda: get_mysql("cp2", criar=True)):
    app = Flask(__name__)

    @app.get("/api/eventos")
    def listar():
        chave = request.args.get("ordenar_por", "data")
        ordem = request.args.get("ordem", "desc").lower()
        if chave not in COLUNAS:
            return jsonify({"erro": "campo de ordenação inválido"}), 400
        if ordem not in ORDEM:
            return jsonify({"erro": "ordem inválida (use asc ou desc)"}), 400
        bruto = request.args.get("tamanho", str(TAMANHO_PADRAO))
        try:
            tamanho = int(bruto)
        except ValueError:
            return jsonify({"erro": "tamanho deve ser inteiro"}), 400
        if tamanho < 1:
            return jsonify({"erro": "tamanho deve ser maior que zero"}), 400
        tamanho = min(tamanho, TAMANHO_MAXIMO)               # teto do servidor

        # coluna e direcao vem SO dos mapas fechados; o LIMIT segue parametrizado
        sql = (f"SELECT id, ip_origem, severidade, tipo, criado_em FROM eventos "
               f"ORDER BY {COLUNAS[chave]} {ORDEM[ordem]}, id LIMIT %s")
        con = conexao_factory()
        try:
            cur = con.cursor(dictionary=True)
            cur.execute(sql, (tamanho,))
            linhas = cur.fetchall()
        finally:
            con.close()
        for l in linhas:
            l["criado_em"] = l["criado_em"].isoformat()
        return jsonify(linhas)

    @app.errorhandler(Exception)
    def erro(e):
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            return jsonify({"erro": e.name}), e.code
        app.logger.exception("falha em /api/eventos")
        return jsonify({"erro": "erro interno"}), 500

    return app


if __name__ == "__main__":
    c = get_mysql("cp2", criar=True)
    preparar(c)
    c.close()
    create_app().run(port=5000, debug=False)
