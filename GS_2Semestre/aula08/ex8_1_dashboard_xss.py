"""Exercicio 8.1 - Dashboard de alertas com defesa contra XSS.

Defesa: o HTML e renderizado com Jinja2 (autoescape ligado para templates .html /
render_template_string), entao <script> vira texto. NUNCA use |safe nem Markup()
em dado vindo do usuario. Mantemos tambem os headers de seguranca (CSP bloqueia
script inline mesmo se alguma falha escapar).
"""
from datetime import datetime

from flask import Flask, redirect, render_template_string, request, url_for

PAGINA = """<!doctype html>
<html lang="pt-br"><head><meta charset="utf-8"><title>Dashboard de Alertas</title></head>
<body>
  <h1>Dashboard de Alertas</h1>
  <form method="post" action="{{ url_for('cadastrar') }}">
    <input name="tipo" placeholder="tipo" required maxlength="50">
    <select name="severidade">
      {% for s in severidades %}<option>{{ s }}</option>{% endfor %}
    </select>
    <input name="descricao" placeholder="descrição" size="60" maxlength="300">
    <button>Cadastrar</button>
  </form>
  <table border="1" cellpadding="4">
    <tr><th>Hora</th><th>Tipo</th><th>Severidade</th><th>Descrição</th></tr>
    {% for a in alertas %}
    <tr><td>{{ a.hora }}</td><td>{{ a.tipo }}</td><td>{{ a.severidade }}</td>
        <td>{{ a.descricao }}</td></tr>   {# {{ }} escapa automaticamente #}
    {% else %}<tr><td colspan="4">Nenhum alerta</td></tr>{% endfor %}
  </table>
</body></html>"""

SEVERIDADES = ("baixa", "media", "alta", "critica")


def create_app():
    app = Flask(__name__)
    alertas = []

    @app.get("/")
    def dashboard():
        return render_template_string(PAGINA, alertas=alertas, severidades=SEVERIDADES)

    @app.post("/alertas")
    def cadastrar():
        tipo = request.form.get("tipo", "").strip()[:50]
        sev = request.form.get("severidade", "")
        if not tipo or sev not in SEVERIDADES:
            return "Dados inválidos", 400
        alertas.append({"hora": datetime.now().strftime("%H:%M:%S"), "tipo": tipo,
                        "severidade": sev, "descricao": request.form.get("descricao", "")[:300]})
        return redirect(url_for("dashboard"))

    @app.after_request
    def headers_seguranca(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        return resp

    return app


if __name__ == "__main__":
    create_app().run(port=5000, debug=False)
