"""Aulas 2 e 3 - funcoes de acesso a dados (MongoDB real ou mongomock; MySQL real)."""
from datetime import datetime

import comum
import ex2_1_inventario as inv
import ex2_2_ingestao_logs as ing
import ex2_3_consultar as cons
import ex3_1_usuarios as usr
import ex3_2_sql_injection as sqli
import ex3_3_relatorio_alertas as rel


# ---------- Aula 2 ----------
def test_2_1_inventario_sem_ip_duplicado(mongo_db):
    col = mongo_db.ativos
    inv.preparar(col)
    assert inv.cadastrar(col, "SRV-DB01", "servidor", "192.168.1.20") == "Ativo cadastrado!"
    assert inv.cadastrar(col, "X", "servidor", "192.168.1.10") == "Erro: IP já cadastrado!"
    assert inv.buscar_por_ip(col, "192.168.1.45")["nome"] == "PC-RH03"
    assert inv.atualizar_status(col, "192.168.1.1", "ativo") == "Status atualizado!"
    assert inv.atualizar_status(col, "9.9.9.9", "ativo").startswith("Erro")
    assert len(inv.listar(col)) == 4
    assert inv.remover(col, "192.168.1.20") == "Ativo removido!"


def test_2_2_ingestao_do_auth_log_do_securapy(mongo_db):
    col = mongo_db.eventos
    assert ing.ingerir(col, comum.LOGS_DIR / "auth.log", "auth") == 23
    top = ing.top_ips_falhas(col)
    assert top[0] == ("185.220.101.1", 11) and top[1] == ("91.240.118.172", 5)
    assert top[2] == ("45.33.32.156", 3)
    doc = col.find_one({"tipo": "FAIL"})
    assert isinstance(doc["timestamp"], datetime) and isinstance(doc["detalhes"], dict)


def test_2_3_consultar_ignora_none(mongo_db):
    col = mongo_db.eventos
    ing.ingerir(col, comum.LOGS_DIR / "auth.log", "auth")
    assert len(cons.consultar(col, tipo="FAIL", ip="185.220.101.1")) == 11
    assert len(cons.consultar(col, fonte="auth")) == 23
    assert len(cons.consultar(col)) == 23
    assert cons.consultar(col, fonte="firewall") == []
    desde = datetime(2025, 2, 20, 8, 15, 30)
    r = cons.consultar(col, tipo="FAIL", desde=desde)
    assert r and all(e["timestamp"] >= desde for e in r)
    ts = [e["timestamp"] for e in r]
    assert ts == sorted(ts)


# ---------- Aula 3 ----------
def test_3_1_usuarios(mysql_conn):
    usr.criar_tabela(mysql_conn)
    for nome, email, nivel in usr.USUARIOS_INICIAIS:
        assert usr.cadastrar(mysql_conn, nome, email, nivel) == "Usuário cadastrado!"
    assert usr.cadastrar(mysql_conn, "Dup", "carlos@empresa.com", 3) == "Erro: email já existe"
    assert usr.cadastrar(mysql_conn, "Nivel", "n@x.com", 9).startswith("Erro")
    assert usr.buscar_por_email(mysql_conn, "ana@empresa.com")["nivel_acesso"] == 5
    assert usr.alterar_nivel(mysql_conn, "bruno@empresa.com", 4) == "Nível atualizado!"
    assert usr.alterar_nivel(mysql_conn, "bruno@empresa.com", 0).startswith("Erro")
    assert [u["nivel_acesso"] for u in usr.listar(mysql_conn)] == [3, 5, 4]
    assert usr.remover(mysql_conn, "bruno@empresa.com") == "Usuário removido!"
    assert usr.remover(mysql_conn, "bruno@empresa.com").startswith("Erro")


def test_3_2_sql_injection_inseguro_vaza_seguro_nao(mysql_conn):
    usr.criar_tabela(mysql_conn)
    for nome, email, nivel in usr.USUARIOS_INICIAIS:
        usr.cadastrar(mysql_conn, nome, email, nivel)
    assert len(sqli.buscar_inseguro(mysql_conn, sqli.ENTRADA_MALICIOSA)) == 3
    assert len(sqli.buscar_seguro(mysql_conn, sqli.ENTRADA_MALICIOSA)) == 0
    assert len(sqli.buscar_seguro(mysql_conn, "Ana Costa")) == 1


def test_3_3_relatorio(mysql_conn):
    rel.preparar(mysql_conn)
    r = rel.gerar_relatorio(mysql_conn)
    assert dict(r["Por severidade"]) == {"alta": 4, "critica": 3, "media": 2, "baixa": 1}
    assert dict(r["Por tipo"]) == {"BRUTE_FORCE": 4, "PORT_SCAN": 3, "XSS": 2, "SQLI": 1}
    assert r["Top IPs de origem"][0] == ("185.220.101.1", 4)
