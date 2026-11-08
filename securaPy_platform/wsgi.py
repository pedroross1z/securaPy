"""Ponto de entrada WSGI (gunicorn wsgi:app)."""
from api.app import create_app
from servicos.bootstrap import construir
from settings import Settings

app = create_app(construir(Settings.from_env()))

if __name__ == "__main__":                # desenvolvimento local: python wsgi.py
    app.run(host="127.0.0.1", port=5000, debug=False)
