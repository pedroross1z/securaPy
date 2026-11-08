"""Migracao/ingestao inicial (Modulo B.3): le os logs pelo nucleo e popula o MongoDB.

    python scripts/ingestao.py [pasta_de_logs]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pymongo import MongoClient  # noqa: E402

from core import coletor  # noqa: E402
from db.mongo_repo import MongoRepo  # noqa: E402
from settings import Settings  # noqa: E402


def ingerir(repo, pasta):
    eventos = coletor.carregar_todos_os_logs(str(pasta))
    return repo.salvar_eventos(eventos, lote="ingestao-inicial")


if __name__ == "__main__":
    cfg = Settings.from_env()
    repo = MongoRepo(MongoClient(cfg.mongo_uri, serverSelectionTimeoutMS=5000)[cfg.mongo_db])
    repo.garantir_indices()
    pasta = sys.argv[1] if len(sys.argv) > 1 else cfg.pasta_logs
    print(f"{ingerir(repo, pasta)} eventos persistidos no MongoDB.")
    print("Top 5 IPs por eventos:", repo.top_ips(5))
