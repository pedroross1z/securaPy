"""CP2 - Exercicio 7: XSS dentro de atributo HTML (A05) - defensivo, so local.

Os payloads
  p1 = <script>alert('xss1')</script>        (quebra o contexto de TEXTO)
  p2 = x" onerror="alert('xss2')             (quebra o contexto de ATRIBUTO, sem <script>)
sao neutralizados porque o Jinja2 escapa < > & ' " (as aspas viram &#34; / &#39;), entao p2 nao
consegue fechar o alt="..." e o onerror nao vira atributo.

Cuidado com `|safe` (ou Markup()): ele diz ao Jinja2 "confie, nao escape" - um unico |safe
sobre dado do usuario reabre exatamente este buraco.

A rota /dashboard-inseguro existe so para comparacao lado a lado (NAO usar em producao).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from comum import get_mongo_db  # noqa: E402

from flask import Flask, render_template_string  # noqa: E402

P1 = "<script>alert('xss1')</script>"
P2 = 'x" onerror="alert(\'xss2\')'

TEMPLATE_SEGURO = """<!doctype html><html lang="pt-br"><meta charset="utf-8"><title>Dashboard</title>
<h1>Incidentes</h1>
<table border="1">
{% for i in incidentes %}
<tr><td>{{ i.titulo }}</td><td><img src="/icone.png" alt="{{ i.ativo }}"></td></tr>
{% endfor %}
</table>"""


def create_app(db=None):
    app = Flask(__name__)
    col = (db if db is not None else get_mongo_db("cp2")).incidentes_xss

    @app.get("/dashboard")
    def dashboard():
        return render_template_string(TEMPLATE_SEGURO, incidentes=list(col.find({}, {"_id": 0})))

    @app.get("/dashboard-inseguro")                       # ⚠️ VULNERAVEL DE PROPOSITO
    def dashboard_inseguro():
        linhas = "".join(f'<tr><td>{i["titulo"]}</td><td><img src="/icone.png" alt="{i["ativo"]}"></td></tr>'
                         for i in col.find({}, {"_id": 0}))
        return f"<!doctype html><title>INSEGURO</title><h1>INSEGURO</h1><table>{linhas}</table>"

    @app.after_request
    def csp(resp):
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    return app


def popular(db):
    db.incidentes_xss.delete_many({})
    db.incidentes_xss.insert_many([{"titulo": P1, "ativo": "SRV-WEB01"},
                                   {"titulo": "Incidente 2", "ativo": P2}])


if __name__ == "__main__":
    banco = get_mongo_db("cp2")
    popular(banco)
    create_app(banco).run(port=5000, debug=False)
