"""Configuracao da plataforma: tudo vem de variaveis de ambiente (ou de um .env local).

Segredos (senhas, chaves, tokens) NUNCA ficam no codigo. O .env fica fora do Git;
.env.example lista as chaves esperadas.
"""
import os
from dataclasses import dataclass, field
from pathlib import Path

RAIZ = Path(__file__).resolve().parent


def carregar_env(arquivo=None):
    """Carrega KEY=VALOR de um .env sem sobrescrever variaveis ja definidas."""
    arquivo = Path(arquivo) if arquivo else RAIZ / ".env"
    if not arquivo.is_file():
        return
    for linha in arquivo.read_text(encoding="utf-8").splitlines():
        linha = linha.strip()
        if linha and not linha.startswith("#") and "=" in linha:
            chave, _, valor = linha.partition("=")
            os.environ.setdefault(chave.strip(), valor.strip())


class ConfiguracaoInvalida(RuntimeError):
    pass


def _obrigatoria(nome):
    valor = os.environ.get(nome)
    if not valor:
        raise ConfiguracaoInvalida(f"variável de ambiente obrigatória ausente: {nome}")
    return valor


def _bool(nome, padrao=False):
    return os.environ.get(nome, str(padrao)).strip().lower() in ("1", "true", "yes", "sim")


@dataclass
class Settings:
    jwt_secret: str
    secret_key: str
    mongo_uri: str = "mongodb://localhost:27017/"
    mongo_db: str = "securapy"
    mysql_host: str = "localhost"
    mysql_port: int = 3306
    mysql_user: str = "root"
    mysql_password: str = ""
    mysql_database: str = "securapy"
    pasta_logs: Path = RAIZ / "logs"
    arquivo_regras: Path = RAIZ / "config" / "regras.json"
    arquivo_blacklist: Path = RAIZ / "config" / "blacklist.txt"
    pasta_modelo: Path = RAIZ / "ml"
    pasta_saida: Path = RAIZ / "saida"
    jwt_ttl_segundos: int = 3600
    exigir_auth_leitura: bool = False
    cookie_seguro: bool = False
    alertas_ativo: bool = False
    alertas_host: str = "0.0.0.0"
    alertas_porta: int = 9999
    admin_email: str = ""
    admin_senha: str = ""
    openai_api_key: str = field(default="", repr=False)

    @classmethod
    def from_env(cls):
        carregar_env()
        return cls(
            jwt_secret=_obrigatoria("JWT_SECRET"),
            secret_key=_obrigatoria("SECRET_KEY"),
            mongo_uri=os.environ.get("MONGO_URI", cls.mongo_uri),
            mongo_db=os.environ.get("MONGO_DB", cls.mongo_db),
            mysql_host=os.environ.get("MYSQL_HOST", cls.mysql_host),
            mysql_port=int(os.environ.get("MYSQL_PORT", cls.mysql_port)),
            mysql_user=os.environ.get("MYSQL_USER", cls.mysql_user),
            mysql_password=_obrigatoria("MYSQL_PASSWORD"),
            mysql_database=os.environ.get("MYSQL_DATABASE", cls.mysql_database),
            pasta_logs=Path(os.environ.get("LOGS_DIR", RAIZ / "logs")),
            exigir_auth_leitura=_bool("EXIGIR_AUTH_LEITURA"),
            cookie_seguro=_bool("COOKIE_SEGURO"),
            alertas_ativo=_bool("ALERTAS_ATIVO"),
            alertas_porta=int(os.environ.get("ALERTAS_PORTA", cls.alertas_porta)),
            admin_email=os.environ.get("ADMIN_EMAIL", ""),
            admin_senha=os.environ.get("ADMIN_PASSWORD", ""),
            openai_api_key=os.environ.get("OPENAI_API_KEY", ""),
        )

    def mysql_config(self, **extra):
        cfg = {"host": self.mysql_host, "port": self.mysql_port, "user": self.mysql_user,
               "password": self.mysql_password, "database": self.mysql_database}
        cfg.update(extra)
        return cfg


def carregar_blacklist(caminho):
    """Um IP por linha; linhas vazias e # ignoradas. Retorna set (busca O(1))."""
    try:
        linhas = Path(caminho).read_text(encoding="utf-8").splitlines()
    except OSError:
        return set()
    return {l.strip() for l in linhas if l.strip() and not l.startswith("#")}
