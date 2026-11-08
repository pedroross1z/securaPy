"""Fixtures compartilhadas. Usa MongoDB/MySQL reais (docker compose up -d) quando
estiverem acessiveis; sem eles, MongoDB cai para mongomock e os testes de MySQL
sao pulados."""
import os
import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[1]
for pasta in [RAIZ, *sorted(RAIZ.glob("aula*")), *sorted(RAIZ.glob("checkpoints/cp*")),
              RAIZ / "checkpoints" / "cp2" / "ex10"]:
    sys.path.insert(0, str(pasta))

# banco de teste isolado: nao mexe nos dados do laboratorio
os.environ["MYSQL_DATABASE"] = "teste_gs2"
os.environ["CP2_DATABASE"] = "teste_gs2"

import comum  # noqa: E402


def _mysql_root():
    import mysql.connector
    cfg = comum.config_mysql(connection_timeout=3)
    cfg.pop("database")
    return mysql.connector.connect(**cfg)


@pytest.fixture(scope="session")
def mysql_disponivel():
    try:
        root = _mysql_root()
    except Exception:
        pytest.skip("MySQL indisponivel (docker compose up -d)")
    root.cursor().execute("CREATE DATABASE IF NOT EXISTS teste_gs2")
    root.close()
    return True


@pytest.fixture()
def mysql_conn(mysql_disponivel):
    conn = comum.get_mysql()
    cur = conn.cursor()
    for tabela in ("alertas_mig", "ativos_mig", "incidentes", "analistas", "usuarios", "alertas", "contas_login",
                   "contas", "ativos", "eventos", "usuarios_aud", "usuarios_cp1"):
        cur.execute(f"DROP TABLE IF EXISTS {tabela}")
    conn.commit()
    yield conn
    conn.close()


@pytest.fixture()
def mongo_db():
    """Banco Mongo limpo para cada teste (real, ou mongomock como plano B)."""
    try:
        from pymongo import MongoClient
        client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=1500)
        client.admin.command("ping")
        client.drop_database("teste_gs2")
        yield client["teste_gs2"]
        client.drop_database("teste_gs2")
    except Exception:
        import mongomock
        yield mongomock.MongoClient()["teste_gs2"]
