"""Exercicio 2.2 - Ingestao dos logs do SecuraPy (1o semestre) no MongoDB.

Reaproveita o parser do coletor.py (GS 1o semestre), converte cada linha em um
documento (timestamp como datetime, detalhes como objeto aninhado) e ranqueia os
IPs com mais falhas usando um pipeline de agregacao.
"""
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from comum import LOGS_DIR, get_mongo_db  # noqa: E402

import coletor  # noqa: E402  (SecuraPy 1o semestre)


def _detalhes_para_dict(texto):
    """'usuario=admin' / 'proto=TCP dst=... dport=22' / 'url=/x status=200' -> dict."""
    return dict(tok.split("=", 1) for tok in texto.split() if "=" in tok)


def evento_para_documento(evento):
    return {
        "timestamp": datetime.strptime(evento["timestamp"], "%Y-%m-%d %H:%M:%S"),
        "fonte": evento["fonte"],
        "tipo": evento["tipo"],
        "ip": evento["ip"],
        "detalhes": _detalhes_para_dict(evento["detalhes"]),
        "linha_original": evento["linha_original"],
    }


def ingerir(colecao, caminho_log, fonte="auth"):
    eventos = coletor.carregar_log(str(caminho_log), fonte)
    docs = [evento_para_documento(e) for e in eventos]
    if docs:
        colecao.insert_many(docs)
    return len(docs)


def top_ips_falhas(colecao, limite=5):
    pipeline = [
        {"$match": {"tipo": "FAIL"}},
        {"$group": {"_id": "$ip", "total": {"$sum": 1}}},
        {"$sort": {"total": -1}},
        {"$limit": limite},
    ]
    return [(l["_id"], l["total"]) for l in colecao.aggregate(pipeline)]


if __name__ == "__main__":
    eventos = get_mongo_db()["eventos"]
    eventos.delete_many({})                       # idempotente: reexecutar nao duplica
    total = ingerir(eventos, LOGS_DIR / "auth.log", "auth")
    print("=== Top IPs por falhas de login ===")
    for ip, n in top_ips_falhas(eventos):
        print(f"{ip} -> {n} falhas")
    print(f"Total de eventos inseridos: {total}")
