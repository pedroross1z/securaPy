"""Utilitarios compartilhados pelos exercicios do 2o semestre.

- Expoe os modulos do SecuraPy (1o semestre) para reaproveitamento.
- Centraliza a conexao com MongoDB / MySQL via variaveis de ambiente
  (nunca deixe usuario/senha fixos no codigo - Aula 2, nota de seguranca).
"""
import os
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent
SECURAPY_1S = RAIZ.parent / "GS_1Semestre" / "securaPy"
LOGS_DIR = SECURAPY_1S / "logs"
SAIDA_DIR = RAIZ / "saida"

# permite `import coletor`, `import enriquecimento`, `import integridade`...
if str(SECURAPY_1S) not in sys.path:
    sys.path.insert(0, str(SECURAPY_1S))


def carregar_env(arquivo=None):
    """Carrega KEY=VALOR de um .env (sem sobrescrever variaveis ja definidas).

    O .env fica fora do Git (ver .gitignore); .env.example mostra as chaves.
    """
    arquivo = Path(arquivo) if arquivo else RAIZ / ".env"
    if not arquivo.is_file():
        return
    for linha in arquivo.read_text(encoding="utf-8").splitlines():
        linha = linha.strip()
        if linha and not linha.startswith("#") and "=" in linha:
            chave, _, valor = linha.partition("=")
            os.environ.setdefault(chave.strip(), valor.strip())


carregar_env()


def get_mongo_db(nome="seguranca"):
    from pymongo import MongoClient
    uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
    client = MongoClient(uri, serverSelectionTimeoutMS=3000)
    client.admin.command("ping")
    return client[nome]


def config_mysql(**extra):
    cfg = {
        "host": os.environ.get("MYSQL_HOST", "localhost"),
        "port": int(os.environ.get("MYSQL_PORT", "3306")),
        "user": os.environ.get("MYSQL_USER", "root"),
        "password": os.environ["MYSQL_PASSWORD"],     # sem default: segredo so via ambiente/.env
        "database": os.environ.get("MYSQL_DATABASE", "seguranca"),
    }
    cfg.update(extra)
    return cfg


def get_mysql(database=None, criar=False):
    """Conecta ao MySQL. criar=True cria o banco (se faltar) antes de selecionar."""
    import mysql.connector
    cfg = config_mysql()
    if database:
        cfg["database"] = database
    if criar:
        raiz = {k: v for k, v in cfg.items() if k != "database"}
        con = mysql.connector.connect(**raiz)
        con.cursor().execute(f"CREATE DATABASE IF NOT EXISTS `{cfg['database']}`")
        con.close()
    return mysql.connector.connect(**cfg)
