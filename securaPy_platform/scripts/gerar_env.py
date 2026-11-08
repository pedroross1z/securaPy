"""Gera um .env com segredos aleatorios (nao sobrescreve um .env existente).

    python scripts/gerar_env.py          # cria .env
    python scripts/gerar_env.py --imprimir
"""
import secrets
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]


def gerar():
    return "\n".join([
        "# gerado por scripts/gerar_env.py - NAO commitar este arquivo",
        f"MYSQL_PASSWORD={secrets.token_urlsafe(18)}",
        "MYSQL_DATABASE=securapy",
        f"JWT_SECRET={secrets.token_hex(32)}",
        f"SECRET_KEY={secrets.token_hex(32)}",
        "ADMIN_EMAIL=admin@securapy.local",
        f"ADMIN_PASSWORD={secrets.token_urlsafe(14)}",
        "ALERTAS_ATIVO=1",
        "# OPENAI_API_KEY=   # opcional; sem chave o assistente usa o modo mock/regras",
        "",
    ])


if __name__ == "__main__":
    destino = RAIZ / ".env"
    if "--imprimir" in sys.argv:
        print(gerar())
    elif destino.exists():
        print(".env já existe; nada foi alterado.")
    else:
        destino.write_text(gerar(), encoding="utf-8")
        print(f".env criado em {destino}")
