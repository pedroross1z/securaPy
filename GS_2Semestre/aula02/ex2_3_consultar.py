"""Exercicio 2.3 - Consulta com filtros dinamicos sobre a colecao de eventos."""
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from comum import LOGS_DIR, get_mongo_db  # noqa: E402


def consultar(colecao, fonte=None, tipo=None, ip=None, desde=None):
    """Monta o filtro apenas com os parametros informados (None e ignorado)."""
    filtro = {}
    if fonte is not None:
        filtro["fonte"] = fonte
    if tipo is not None:
        filtro["tipo"] = tipo
    if ip is not None:
        filtro["ip"] = ip
    if desde is not None:
        filtro["timestamp"] = {"$gte": desde}
    return list(colecao.find(filtro, {"_id": 0}).sort("timestamp", 1))


if __name__ == "__main__":
    from ex2_2_ingestao_logs import ingerir

    eventos = get_mongo_db()["eventos"]
    if eventos.count_documents({}) == 0:
        ingerir(eventos, LOGS_DIR / "auth.log", "auth")

    r = consultar(eventos, tipo="FAIL", ip="185.220.101.1")
    print(f"consultar(tipo=FAIL, ip=185.220.101.1) -> {len(r)} eventos")
    r = consultar(eventos, fonte="auth")
    print(f"consultar(fonte=auth) -> {len(r)} eventos")
    r = consultar(eventos, tipo="FAIL", desde=datetime(2025, 2, 20, 8, 20))
    print(f"consultar(tipo=FAIL, desde=08:20) -> {len(r)} eventos")
