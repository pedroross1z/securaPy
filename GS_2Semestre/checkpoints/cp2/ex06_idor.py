"""CP2 - Exercicio 6: controle de acesso quebrado (A01 / IDOR) com X-API-Key.

  401 = "nao sei quem voce e"      (sem header / chave desconhecida)
  403 = "sei quem voce e e voce nao pode"
  O 403 e identico exista o incidente ou nao, para quem nao e dono nem admin
  (senao o status viraria um oraculo de existencia de IDs). Apenas nivel >= 5,
  que ja pode apagar qualquer incidente, recebe 404 para IDs inexistentes.

A chave nunca e guardada em claro: a tabela guarda o SHA-256 da chave e a consulta
parametrizada compara o hash do header.
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from comum import get_mysql  # noqa: E402

from flask import Flask, g, jsonify, request  # noqa: E402

NIVEL_ADMIN = 5
ANALISTAS = [(1, "ana", "key-ana-001", 5), (2, "bruno", "key-bruno-002", 2)]
INCIDENTES = [(1, 1, "Brute force SSH", "critica"), (2, 2, "Phishing no RH", "media")]


def _hash(chave):
    return hashlib.sha256(chave.encode()).hexdigest()


def preparar(con):
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS incidentes")
    cur.execute("DROP TABLE IF EXISTS analistas")
    cur.execute("CREATE TABLE analistas (id INT PRIMARY KEY, nome VARCHAR(50), "
                "api_key CHAR(64) UNIQUE NOT NULL, nivel INT NOT NULL)")
    cur.execute("CREATE TABLE incidentes (id INT PRIMARY KEY, dono_id INT NOT NULL, titulo VARCHAR(100), "
                "severidade VARCHAR(20), status VARCHAR(20) DEFAULT 'aberto', "
                "FOREIGN KEY (dono_id) REFERENCES analistas(id))")
    cur.executemany("INSERT INTO analistas VALUES (%s, %s, %s, %s)",
                    [(i, n, _hash(k), nv) for i, n, k, nv in ANALISTAS])
    cur.executemany("INSERT INTO incidentes (id, dono_id, titulo, severidade) VALUES (%s, %s, %s, %s)", INCIDENTES)
    con.commit()


def create_app(conexao_factory=lambda: get_mysql("cp2", criar=True)):
    app = Flask(__name__)

    def consulta(sql, params=(), um=False, escrita=False):
        con = conexao_factory()
        try:
            cur = con.cursor(dictionary=True)
            cur.execute(sql, params)
            if escrita:
                con.commit()
                return cur.rowcount
            return cur.fetchone() if um else cur.fetchall()
        finally:
            con.close()

    @app.before_request
    def autenticar():
        chave = request.headers.get("X-API-Key", "")
        analista = (consulta("SELECT id, nome, nivel FROM analistas WHERE api_key = %s",
                             (_hash(chave),), um=True) if chave else None)
        if not analista:
            return jsonify({"erro": "autenticação necessária"}), 401
        g.analista = analista

    def negado():
        return jsonify({"erro": "acesso negado"}), 403

    @app.get("/api/incidentes")
    def listar():
        return jsonify(consulta("SELECT id, titulo, severidade, status FROM incidentes WHERE dono_id = %s",
                                (g.analista["id"],)))

    @app.get("/api/incidentes/<int:iid>")
    def obter(iid):
        inc = consulta("SELECT id, dono_id, titulo, severidade, status FROM incidentes WHERE id = %s",
                       (iid,), um=True)
        if inc and inc["dono_id"] == g.analista["id"]:
            return jsonify(inc)
        if g.analista["nivel"] >= NIVEL_ADMIN and not inc:
            return jsonify({"erro": "não encontrado"}), 404
        return negado()                                   # nao-dono: mesma resposta exista ou nao

    @app.delete("/api/incidentes/<int:iid>")
    def apagar(iid):
        if g.analista["nivel"] < NIVEL_ADMIN:
            return negado()
        if consulta("DELETE FROM incidentes WHERE id = %s", (iid,), escrita=True) == 0:
            return jsonify({"erro": "não encontrado"}), 404
        return jsonify({"mensagem": "Removido"})

    @app.errorhandler(404)
    def rota(e):
        return jsonify({"erro": "rota não existe"}), 404

    return app


if __name__ == "__main__":
    c = get_mysql("cp2", criar=True)
    preparar(c)
    c.close()
    create_app().run(port=5000, debug=False)
