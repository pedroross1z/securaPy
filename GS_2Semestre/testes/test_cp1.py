"""Testes do Check Point 1 (cp1_2semestre.md)."""
import ex01_ativos_sql as e1
import ex02_vulnerabilidades_mongo as e2
import ex03_top_ips as e3
import ex04_sql_injection as e4
import ex05_transacao as e5
import ex06_indice as e6
import ex07_08_09_ml as ml
import ex10_pipeline_siem as e10


def test_cp1_ex01_crud_ativos(mysql_conn):
    e1.criar_tabela(mysql_conn)
    for a in e1.ATIVOS:
        assert e1.inserir(mysql_conn, *a) == (True, "1 registro inserido")
    assert e1.listar_por_tipo(mysql_conn, "servidor") == [("SRV-WEB01", "192.168.1.10", "alta", "ativo")]
    assert e1.atualizar_status(mysql_conn, "SW-CORE01", "ativo") == "1 registro atualizado"
    ok, msg = e1.inserir(mysql_conn, "DUP", "192.168.1.10", "servidor", "alta")
    assert not ok and "UNIQUE" in msg
    assert e1.remover(mysql_conn, "PC-RH03") == "1 registro removido"
    assert len(e1.listar_por_tipo(mysql_conn, "estacao")) == 0


def test_cp1_ex02_vulnerabilidades(mongo_db):
    col = mongo_db.vulnerabilidades
    e2.popular(col)
    assert [v["cve_id"] for v in e2.buscar_por_severidade(col, "Alta")] == ["CVE-2024-001"]
    assert e2.marcar_corrigida(col, "CVE-2024-001") == "1 documento modificado"
    assert e2.abertas(col) == 1
    assert e2.remover(col, "CVE-2024-002") == 1


def test_cp1_ex03_top_ips(mongo_db):
    col = mongo_db.ev
    col.insert_many([dict(e) for e in e3.EVENTOS])
    assert e3.top_ips_fail(col) == [("185.220.101.1", 4), ("91.240.118.172", 2), ("45.33.32.156", 1)]


def test_cp1_ex04_sqli(mysql_conn):
    e4.preparar(mysql_conn)
    assert len(e4.buscar_inseguro(mysql_conn, e4.ENTRADA)) == 3
    assert len(e4.buscar_seguro(mysql_conn, e4.ENTRADA)) == 0
    assert e4.buscar_seguro(mysql_conn, "ana") == [("ana", "ana@x.com")]


def test_cp1_ex05_rollback(mysql_conn):
    e5.preparar(mysql_conn)
    assert e5.transferir(mysql_conn, 1, 2, 200) is True
    assert (e5.saldo(mysql_conn, 1), e5.saldo(mysql_conn, 2)) == (800, 700)
    assert e5.transferir(mysql_conn, 1, 99, 100) is False
    assert e5.saldo(mysql_conn, 1) == 800                   # debito desfeito pelo rollback
    assert e5.transferir(mysql_conn, 1, 2, 5000) is False   # CHECK saldo >= 0 tambem faz rollback
    assert (e5.saldo(mysql_conn, 1), e5.saldo(mysql_conn, 2)) == (800, 700)


def test_cp1_ex06_indice(mongo_db):
    col = mongo_db.idx
    col.insert_many(e6.gerar_eventos())
    col.create_index("ip")
    assert col.count_documents({}) == 1000
    assert e6.contar_por_ip(col, "185.220.101.1") == 250


def test_cp1_ex07_08_09():
    modelo, acc = ml.ex07_classificador()
    assert acc >= 0.66 and modelo.predict(ml.CASO_NOVO)[0] == 1
    assert [i for i, v in enumerate(ml.ex08_anomalias()) if v == -1] == [4, 7]
    m = ml.ex09_metricas()
    assert m["matriz"] == [[8, 0], [1, 1]] and m["recall"] == 0.5 and m["acuracia"] == 0.9


def test_cp1_ex10_pipeline(mongo_db):
    col = mongo_db.auth
    assert e10.ingerir(col) == 23
    contagens = dict(e10.fails_por_ip(col))
    assert contagens["185.220.101.1"] == 11 and contagens["91.240.118.172"] == 5
    assert contagens["45.33.32.156"] == 3 and contagens["192.168.1.10"] == 0
    X, y = e10.montar_dataset(e10.fails_por_ip(col))
    assert sum(y) == 2
    assert e10.treinar_e_prever(X, y, 8) == 1
    assert e10.treinar_e_prever(X, y, 1) == 0
