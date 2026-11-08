"""Fixtures. MongoDB/MySQL reais (laboratorio: `docker compose up -d` em GS_2Semestre) quando
acessiveis; sem eles, MongoDB cai para mongomock e os testes de MySQL sao pulados.

Credenciais do MySQL de teste: TEST_MYSQL_PASSWORD (ou o .env do laboratorio ../GS_2Semestre/.env)."""
import os
import sys
from pathlib import Path

import mysql.connector
import pytest

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

from db.mongo_repo import MongoRepo  # noqa: E402
from db.mysql_repo import UsuariosRepo  # noqa: E402
from ia.assistente import Assistente, ClienteMock  # noqa: E402
from ml import treinar  # noqa: E402
from ml.classificar import Classificador  # noqa: E402
from servicos.analise import Plataforma  # noqa: E402
from settings import Settings, carregar_blacklist  # noqa: E402

BANCO_TESTE = "teste_plataforma"


def _senha_mysql():
    if os.environ.get("TEST_MYSQL_PASSWORD"):
        return os.environ["TEST_MYSQL_PASSWORD"]
    lab = RAIZ.parent / "GS_2Semestre" / ".env"
    if lab.is_file():
        for linha in lab.read_text(encoding="utf-8").splitlines():
            if linha.startswith("MYSQL_PASSWORD="):
                return linha.partition("=")[2].strip()
    return ""


CFG_MYSQL = {"host": os.environ.get("TEST_MYSQL_HOST", "localhost"), "port": 3306, "user": "root",
             "password": _senha_mysql()}


@pytest.fixture(scope="session")
def mysql_disponivel():
    try:
        con = mysql.connector.connect(**CFG_MYSQL, connection_timeout=3)
    except Exception:
        pytest.skip("MySQL indisponivel para testes")
    con.cursor().execute(f"CREATE DATABASE IF NOT EXISTS {BANCO_TESTE}")
    con.close()


@pytest.fixture()
def usuarios_repo(mysql_disponivel):
    def fabrica():
        return mysql.connector.connect(**CFG_MYSQL, database=BANCO_TESTE)
    con = fabrica()
    con.cursor().execute("DROP TABLE IF EXISTS usuarios")
    con.commit()
    con.close()
    repo = UsuariosRepo(fabrica)
    repo.criar_tabelas()
    return repo


@pytest.fixture()
def mongo_db():
    try:
        from pymongo import MongoClient
        c = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=1500)
        c.admin.command("ping")
        c.drop_database(BANCO_TESTE)
        yield c[BANCO_TESTE]
        c.drop_database(BANCO_TESTE)
    except Exception:
        import mongomock
        yield mongomock.MongoClient()[BANCO_TESTE]


@pytest.fixture(scope="session")
def pasta_modelo(tmp_path_factory):
    pasta = tmp_path_factory.mktemp("modelo")
    treinar.treinar_e_salvar(pasta)
    return pasta


@pytest.fixture()
def settings(tmp_path, pasta_modelo):
    return Settings(jwt_secret="j" * 40, secret_key="s" * 40, pasta_modelo=pasta_modelo,
                    pasta_saida=tmp_path / "saida", mysql_database=BANCO_TESTE)


@pytest.fixture()
def plataforma(settings, mongo_db, usuarios_repo):
    mongo = MongoRepo(mongo_db)
    mongo.garantir_indices()
    return Plataforma(
        settings, mongo, usuarios_repo, Classificador(settings.pasta_modelo, treinar_se_ausente=False),
        Assistente(ClienteMock()), carregar_blacklist(settings.arquivo_blacklist),
        consultar_geo=lambda ip: {"ip": ip, "cidade": "Berlin", "pais": "DE", "org": "Org Teste",
                                  "privado": False})


@pytest.fixture()
def app(plataforma):
    from api.app import create_app
    plataforma.usuarios.criar("Admin", "admin@x.com", "Senha@12345", 5)
    plataforma.usuarios.criar("Ana", "ana@x.com", "Senha@12345", 1)
    a = create_app(plataforma)
    a.config["TESTING"] = False        # mantem os error handlers em acao
    return a


@pytest.fixture()
def client(app):
    return app.test_client()


def _token(client, email="admin@x.com", senha="Senha@12345"):
    r = client.post("/api/login", json={"email": email, "senha": senha})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.json["token"]


@pytest.fixture()
def auth(client):
    return {"Authorization": f"Bearer {_token(client)}"}


@pytest.fixture()
def auth_baixo(client):
    return {"Authorization": f"Bearer {_token(client, 'ana@x.com')}"}


@pytest.fixture()
def analisado(client, auth):
    r = client.post("/api/analisar", json={}, headers=auth)
    assert r.status_code == 200
    return r.json
