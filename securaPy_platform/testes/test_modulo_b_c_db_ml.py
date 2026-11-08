"""Modulos B (persistencia) e C (machine learning)."""
import json
import shutil

import pytest

from core import coletor
from db.mongo_repo import MongoRepo, RepositorioIndisponivel
from db.mysql_repo import BancoIndisponivel, ErroValidacao, UsuarioDuplicado, UsuarioInexistente, UsuariosRepo
from ml import classificar, treinar
from ml.anomalias import detectar_anomalias
from ml.features import extrair_features
from settings import carregar_blacklist
from testes.conftest import RAIZ

LOGS = str(RAIZ / "logs")
BLACKLIST = carregar_blacklist(RAIZ / "config" / "blacklist.txt")


# ------------------------------------------------------------------ B - Mongo
def test_b1_ingere_58_eventos_e_nao_duplica(mongo_db):
    repo = MongoRepo(mongo_db)
    repo.garantir_indices()
    eventos = coletor.carregar_todos_os_logs(LOGS)
    assert repo.salvar_eventos(eventos, lote="x") == 58
    assert repo.salvar_eventos(eventos, lote="x") == 58            # reingerir substitui o lote
    assert repo.contagem_eventos() == 58
    assert repo.contagem_por_fonte() == {"auth": 23, "firewall": 17, "web": 18}


def test_b2_top_ips_por_agregacao(mongo_db):
    repo = MongoRepo(mongo_db)
    repo.salvar_eventos(coletor.carregar_todos_os_logs(LOGS))
    top = repo.top_ips(5)
    assert top[0][0] == "185.220.101.1" and len(top) == 5
    assert [t for _, t in top] == sorted((t for _, t in top), reverse=True)


def test_b_filtros_por_fonte_tipo_ip_e_periodo(mongo_db):
    repo = MongoRepo(mongo_db)
    repo.salvar_eventos(coletor.carregar_todos_os_logs(LOGS))
    itens, total = repo.buscar_eventos(fonte="auth", tipo="FAIL", ip="185.220.101.1")
    assert total == 11 and all(i["tipo"] == "FAIL" for i in itens)
    _, total = repo.buscar_eventos(desde="2025-02-20 08:20:00", ate="2025-02-20 08:20:10")
    assert 0 < total < 58
    itens, total = repo.buscar_eventos(pagina=2, tamanho=10)
    assert len(itens) == 10 and total == 58


def test_b_indices_criados(mongo_db):
    repo = MongoRepo(mongo_db)
    repo.garantir_indices()
    chaves = {tuple(i["key"].keys()) if hasattr(i["key"], "keys") else tuple(k for k, _ in i["key"])
              for i in mongo_db.eventos.list_indexes()}
    assert ("ip",) in chaves and ("timestamp",) in chaves


def test_b_evento_malformado_e_descartado_sem_derrubar_o_lote(mongo_db):
    repo = MongoRepo(mongo_db)
    ok = {"timestamp": "2025-02-20 08:15:01", "fonte": "auth", "tipo": "FAIL", "ip": "1.1.1.1", "detalhes": "x"}
    assert repo.salvar_eventos([ok, {"ip": "sem-timestamp"}, {"timestamp": "ontem", "ip": "x"}]) == 1


def test_b_obter_alerta_id_invalido(mongo_db):
    repo = MongoRepo(mongo_db)
    with pytest.raises(ValueError):
        repo.obter_alerta("nao-e-objectid")
    assert repo.obter_alerta("a" * 24) is None


def test_b_mongo_fora_do_ar_vira_excecao_de_repositorio():
    from pymongo import MongoClient
    repo = MongoRepo(MongoClient("mongodb://localhost:1", serverSelectionTimeoutMS=200)["x"])
    with pytest.raises(RepositorioIndisponivel):
        repo.contagem_eventos()


# ------------------------------------------------------------------ B - MySQL
def test_b3_email_duplicado_tratado(usuarios_repo):
    usuarios_repo.criar("Carlos", "carlos@x.com", "Senha@12345", 3)
    with pytest.raises(UsuarioDuplicado):
        usuarios_repo.criar("Outro", "CARLOS@x.com", "Senha@12345", 1)
    assert len(usuarios_repo.listar()) == 1


def test_b4_sql_injection_no_login_neutralizado(usuarios_repo):
    usuarios_repo.criar("Ana", "ana@x.com", "Senha@12345", 2)
    assert usuarios_repo.autenticar("' OR '1'='1", "' OR '1'='1") is None
    assert usuarios_repo.autenticar("ana@x.com' --", "x") is None
    assert usuarios_repo.autenticar("ana@x.com", "Senha@12345")["nivel_acesso"] == 2
    assert usuarios_repo.autenticar("ana@x.com", "errada") is None


def test_b_crud_validacoes_e_senha_nunca_em_texto_puro(usuarios_repo):
    usuarios_repo.criar("Ana", "ana@x.com", "Senha@12345", 2)
    for args in [("", "a@x.com", "Senha@12345", 1), ("A", "sem-arroba", "Senha@12345", 1),
                 ("A", "a@x.com", "curta", 1), ("A", "a@x.com", "Senha@12345", 9),
                 ("A", "a@x.com", "Senha@12345", True)]:
        with pytest.raises(ErroValidacao):
            usuarios_repo.criar(*args)
    usuarios_repo.alterar_nivel("ana@x.com", 4)
    assert usuarios_repo.buscar_por_email("ana@x.com")["nivel_acesso"] == 4
    with pytest.raises(ErroValidacao):
        usuarios_repo.alterar_nivel("ana@x.com", 0)
    with pytest.raises(UsuarioInexistente):
        usuarios_repo.alterar_nivel("x@x.com", 3)
    con = usuarios_repo._factory()
    cur = con.cursor()
    cur.execute("SELECT senha_hash FROM usuarios")
    assert "Senha@12345" not in cur.fetchone()[0]
    con.close()
    usuarios_repo.remover("ana@x.com")
    with pytest.raises(UsuarioInexistente):
        usuarios_repo.remover("ana@x.com")


def test_b_mysql_fora_do_ar_vira_banco_indisponivel():
    import mysql.connector
    repo = UsuariosRepo(lambda: mysql.connector.connect(host="localhost", port=1, user="x", password="x",
                                                       connection_timeout=1))
    with pytest.raises(BancoIndisponivel):
        repo.listar()


# ------------------------------------------------------------------ C - ML
@pytest.fixture()
def feats():
    return extrair_features(coletor.carregar_todos_os_logs(LOGS), BLACKLIST)


def test_c1_treino_reporta_metricas_e_salva_hash(tmp_path):
    rel, texto = treinar.treinar_e_salvar(tmp_path)
    assert {"precisao", "recall", "f1"} <= set(rel["teste"])
    assert rel["teste"]["f1"] > 0.8 and "precision" in texto
    assert set(rel["validacao_cruzada_5_folds"]) == {"precision", "recall", "f1"}
    assert len((tmp_path / "modelo.pkl.sha256").read_text().strip()) == 64
    assert json.loads((tmp_path / "metricas.json").read_text())["teste"]["f1"] == rel["teste"]["f1"]


def test_c2_ip_atacante_tem_risco_alto(settings, feats):
    c = classificar.Classificador(settings.pasta_modelo, treinar_se_ausente=False)
    r = c.pontuar_ip("185.220.101.1", feats)
    assert r["nivel"] == "ALTO" and r["rotulo"] == "ataque"


def test_c3_ip_interno_normal(settings, feats):
    c = classificar.Classificador(settings.pasta_modelo, treinar_se_ausente=False)
    r = c.pontuar_ip("192.168.1.10", feats)
    assert r["rotulo"] == "normal" and r["nivel"] == "BAIXO"
    ranking = c.pontuar(feats)
    assert [x["score"] for x in ranking] == sorted((x["score"] for x in ranking), reverse=True)
    assert ranking[-1]["rotulo"] == "normal"


def test_c4_integridade_do_modelo(tmp_path, pasta_modelo):
    destino = tmp_path / "m"
    shutil.copytree(pasta_modelo, destino)
    assert classificar.carregar_modelo(destino) is not None
    with open(destino / "modelo.pkl", "ab") as f:
        f.write(b"\x00")
    with pytest.raises(classificar.ModeloAdulterado, match="modificado"):
        classificar.carregar_modelo(destino)


def test_c_modelo_ausente_treina_ou_recusa(tmp_path):
    with pytest.raises(classificar.ModeloAusente):
        classificar.Classificador(tmp_path, treinar_se_ausente=False).modelo
    assert classificar.Classificador(tmp_path, treinar_se_ausente=True).modelo is not None


def test_c_bonus_isolation_forest(feats):
    assert [a["ip"] for a in detectar_anomalias(feats)] == ["185.220.101.1"]
    assert detectar_anomalias({"1.1.1.1": feats["185.220.101.1"]}) == []          # populacao pequena
