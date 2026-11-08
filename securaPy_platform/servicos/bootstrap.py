"""Monta a Plataforma a partir das Settings: conexoes, tabelas, indices, admin inicial, servidor de alertas."""
import logging
import time

import mysql.connector
from pymongo import MongoClient

from alertas import servidor_alertas
from db.mongo_repo import MongoRepo
from db.mysql_repo import UsuarioDuplicado, UsuariosRepo
from ia.assistente import Assistente, criar_cliente
from ml.classificar import Classificador
from servicos.analise import Plataforma
from settings import carregar_blacklist

log = logging.getLogger("securapy.bootstrap")


def esperar(descricao, funcao, tentativas=30, intervalo=2.0):
    """Os bancos podem demorar a subir (docker compose): tenta de novo em vez de cair."""
    for i in range(1, tentativas + 1):
        try:
            return funcao()
        except Exception as e:
            log.warning("aguardando %s (%d/%d): %s", descricao, i, tentativas, type(e).__name__)
            time.sleep(intervalo)
    raise RuntimeError(f"{descricao} não ficou disponível")


def garantir_banco_mysql(settings):
    """Cria o schema se ainda nao existir (no compose o MYSQL_DATABASE ja vem criado)."""
    cfg = settings.mysql_config()
    banco = cfg.pop("database")
    con = mysql.connector.connect(**cfg)
    try:
        con.cursor().execute(f"CREATE DATABASE IF NOT EXISTS `{banco}`")
    finally:
        con.close()


def construir(settings, espera=True):
    mongo_client = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=5000)
    mongo = MongoRepo(mongo_client[settings.mongo_db])
    usuarios = UsuariosRepo(lambda: mysql.connector.connect(**settings.mysql_config(connection_timeout=5)))

    def preparar():
        garantir_banco_mysql(settings)
        usuarios.criar_tabelas()
        mongo.garantir_indices()
        semear_admin(usuarios, settings)

    if espera:
        esperar("MongoDB e MySQL", preparar)
    else:
        preparar()

    transmitir = None
    if settings.alertas_ativo:
        servidor_alertas.iniciar_em_thread(settings.alertas_host, settings.alertas_porta)
        transmitir = servidor_alertas.broadcast_alerta
        log.info("servidor de alertas em tempo real na porta %s", settings.alertas_porta)

    return Plataforma(settings, mongo, usuarios, Classificador(settings.pasta_modelo),
                      Assistente(criar_cliente(settings.openai_api_key)),
                      carregar_blacklist(settings.arquivo_blacklist), transmitir=transmitir)


def semear_admin(usuarios, settings):
    """Cria o primeiro operador (nivel 5) com credenciais do ambiente, se ainda nao houver usuarios."""
    if not (settings.admin_email and settings.admin_senha) or usuarios.listar():
        return
    try:
        usuarios.criar("Administrador", settings.admin_email, settings.admin_senha, 5)
        log.info("operador administrador inicial criado (%s)", settings.admin_email)
    except UsuarioDuplicado:
        pass
