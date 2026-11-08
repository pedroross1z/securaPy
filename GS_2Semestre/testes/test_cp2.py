"""Testes do Check Point 2 cumulativo (cp2_cumulativo_2semestre.md)."""
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
from werkzeug.serving import make_server

import comum
import ex01_recomendar as e1
import ex02_migracao as e2
import ex03_ttl_janela as e3
import ex04_auditoria as e4
import ex05_order_by as e5
import ex06_idor as e6
import ex07_xss_atributo as e7
import ex08_modelo_api as e8
import ex09_rate_limit_anomalia as e9


# ---------- Ex 1 ----------
def test_cp2_ex01_recomendacoes():
    esperado = {"credenciais_do_SOC": ("MySQL", "CP", "A07"), "telemetria_de_sensores": ("MongoDB", "AP", "A09"),
                "trilha_de_auditoria": ("MongoDB", "CP", "A08"), "carrinho_de_licencas": ("MySQL", "CP", "A06"),
                "cache_de_sessoes": ("MongoDB", "AP", "A07")}
    for nome, (banco, cap, risco) in esperado.items():
        r = e1.recomendar(e1.PERFIS[nome])
        assert (r["banco"], r["cap"]) == (banco, cap) and r["risco_owasp"].startswith(risco)
        assert "inaceitável" in r["justificativa"]           # nomeia o erro, nao repete a sigla


def test_cp2_ex01_valida_perfil():
    with pytest.raises(ValueError):
        e1.recomendar({"schema_fixo": True})
    with pytest.raises(ValueError):
        e1.recomendar({**e1.PERFIS["cache_de_sessoes"], "dado_sensivel": "sim"})


# ---------- Ex 2 ----------
def test_cp2_ex02_migracao_integra(mysql_conn, mongo_db):
    e2.criar_e_popular(mysql_conn)
    assert e2.migrar(mysql_conn, mongo_db.alertas) == 3
    assert e2.verificar(mysql_conn, mongo_db.alertas) == (3, 3, True)
    assert mongo_db.alertas.count_documents({"ativo.criticidade": "alta"}) == 2
    assert mongo_db.alertas.find_one({"tipo": "XSS"})["ativo"]["nome"] == "PC-RH03"
    mongo_db.alertas.delete_one({"tipo": "XSS"})              # simula perda: verificacao deve acusar
    assert e2.verificar(mysql_conn, mongo_db.alertas)[2] is False


# ---------- Ex 3 ----------
def test_cp2_ex03_ttl_e_janela(mongo_db):
    col = mongo_db.eventos
    e3.preparar(col)
    assert e3.gerar(col, 200) == 200
    assert e3.ttl_ativo(col)
    dist = e3.falhas_por_hora(col)
    assert sum(t for _, t in dist) == col.count_documents({"tipo": "FAIL"})
    texto, (hora, total) = e3.histograma(dist)
    assert "<- pico" in texto and total == max(t for _, t in dist)
    seis_h = sum(t for _, t in e3.falhas_por_hora(col, datetime.now(timezone.utc) - timedelta(hours=6)))
    assert seis_h < sum(t for _, t in dist)


# ---------- Ex 4 ----------
def test_cp2_ex04_auditoria_registra_tudo(mysql_conn, mongo_db):
    e4.preparar(mysql_conn)
    aud = mongo_db.auditoria
    assert e4.alterar_nivel(mysql_conn, aud, 1, 2, 4)[0] == "ACEITO" and e4.nivel_atual(mysql_conn, 2) == 4
    assert e4.alterar_nivel(mysql_conn, aud, 2, 3, 5) == ("RECUSADO", "admin sem privilégio")
    assert e4.nivel_atual(mysql_conn, 3) == 1
    assert e4.alterar_nivel(mysql_conn, aud, 1, 1, 9) == ("RECUSADO", "auto-promoção")
    assert e4.nivel_atual(mysql_conn, 1) == 5
    assert e4.alterar_nivel(mysql_conn, aud, 1, 99, 3) == ("RECUSADO", "alvo inexistente")
    assert aud.count_documents({}) == 4 and aud.count_documents({"resultado": "RECUSADO"}) == 3
    doc = aud.find_one({"resultado": "ACEITO"})
    assert (doc["quem"], doc["alvo"], doc["nivel_anterior"], doc["nivel_novo"]) == (1, 2, 2, 4)


def test_cp2_ex04_falha_de_auditoria_nao_confirma_a_alteracao(mysql_conn):
    e4.preparar(mysql_conn)

    class AuditoriaQuebrada:
        def insert_one(self, _):
            raise RuntimeError("mongo fora do ar")
    r, motivo = e4.alterar_nivel(mysql_conn, AuditoriaQuebrada(), 1, 2, 4)
    assert r == "RECUSADO" and "erro interno" in motivo
    assert e4.nivel_atual(mysql_conn, 2) == 2                 # fail closed: sem trilha, sem privilegio


# ---------- Ex 5 ----------
@pytest.fixture()
def c5(mysql_conn):
    e5.preparar(mysql_conn)
    return e5.create_app(comum.get_mysql).test_client()


def test_cp2_ex05_ordenacao_whitelist(c5):
    r = c5.get("/api/eventos?ordenar_por=sev&ordem=desc&tamanho=5")
    assert r.status_code == 200 and len(r.json) == 5
    ordem = ["baixa", "media", "alta", "critica"]
    sev = [ordem.index(e["severidade"]) for e in r.json]
    assert sev == sorted(sev, reverse=True)
    ips = [e["ip_origem"] for e in c5.get("/api/eventos?ordenar_por=ip&ordem=asc").json]
    assert ips == sorted(ips)


def test_cp2_ex05_rejeita_injecao_e_valida_tamanho(c5):
    r = c5.get("/api/eventos?ordenar_por=criado_em,(SELECT+1)&ordem=asc")
    assert r.status_code == 400 and r.json == {"erro": "campo de ordenação inválido"}
    assert c5.get("/api/eventos?ordenar_por=criado_em").status_code == 400      # nome real da coluna tambem
    assert c5.get("/api/eventos?ordem=desc;DROP TABLE eventos").status_code == 400
    r = c5.get("/api/eventos?tamanho=abc")
    assert r.status_code == 400 and r.json == {"erro": "tamanho deve ser inteiro"}
    assert c5.get("/api/eventos?tamanho=0").status_code == 400
    assert c5.get("/api/eventos?tamanho=100000").status_code == 200
    assert len(c5.get("/api/eventos?tamanho=100000").json) <= 100
    assert c5.get("/api/eventos?tamanho=1;DROP TABLE eventos").status_code == 400


# ---------- Ex 6 ----------
@pytest.fixture()
def c6(mysql_conn):
    e6.preparar(mysql_conn)
    return e6.create_app(comum.get_mysql).test_client()


@pytest.mark.parametrize("metodo,url,chave,status", [
    ("get", "/api/incidentes/1", "key-ana-001", 200),
    ("get", "/api/incidentes/1", "key-bruno-002", 403),
    ("get", "/api/incidentes/1", None, 401),
    ("get", "/api/incidentes/1", "key-inexistente", 401),
    ("get", "/api/incidentes/999", "key-ana-001", 404),
    ("delete", "/api/incidentes/1", "key-bruno-002", 403),
    ("delete", "/api/incidentes/2", "key-ana-001", 200),
])
def test_cp2_ex06_matriz_de_acesso(c6, metodo, url, chave, status):
    headers = {"X-API-Key": chave} if chave else {}
    assert getattr(c6, metodo)(url, headers=headers).status_code == status


def test_cp2_ex06_lista_so_os_proprios_e_403_nao_vaza_existencia(c6):
    r = c6.get("/api/incidentes", headers={"X-API-Key": "key-bruno-002"})
    assert [i["id"] for i in r.json] == [2]
    existe = c6.get("/api/incidentes/1", headers={"X-API-Key": "key-bruno-002"})
    nao_existe = c6.get("/api/incidentes/999", headers={"X-API-Key": "key-bruno-002"})
    assert existe.status_code == nao_existe.status_code == 403 and existe.json == nao_existe.json


def test_cp2_ex06_chave_nao_fica_em_claro_e_sqli_no_header(c6, mysql_conn):
    cur = mysql_conn.cursor()
    cur.execute("SELECT api_key FROM analistas")
    assert all("key-" not in k for (k,) in cur.fetchall())
    assert c6.get("/api/incidentes", headers={"X-API-Key": "' OR '1'='1"}).status_code == 401


# ---------- Ex 7 ----------
def test_cp2_ex07_xss_em_texto_e_atributo(mongo_db):
    e7.popular(mongo_db)
    c = e7.create_app(mongo_db).test_client()
    seguro = c.get("/dashboard").get_data(as_text=True)
    assert "<script>" not in seguro and "&lt;script&gt;" in seguro                    # p1 como texto
    assert 'alt="x&#34; onerror=&#34;alert(&#39;xss2&#39;)"' in seguro                # p2 preso no alt
    assert ' onerror="' not in seguro
    inseguro = c.get("/dashboard-inseguro").get_data(as_text=True)
    assert "<script>alert('xss1')</script>" in inseguro and 'onerror="alert' in inseguro
    for rota in ("/dashboard", "/dashboard-inseguro"):
        assert c.get(rota).headers["Content-Security-Policy"] == "default-src 'self'"


# ---------- Ex 8 ----------
@pytest.fixture(scope="module")
def modelo8():
    return e8.treinar()


def test_cp2_ex08_triagem_e_validacao(mongo_db, modelo8):
    c = e8.create_app(mongo_db, modelo8).test_client()
    r = c.post("/api/triagem", json={"features": [12, 7, 90000, 3]})
    assert r.status_code == 200 and r.json["risco"] == "alto" and 0.5 <= r.json["confianca"] <= 1
    assert c.post("/api/triagem", json={"features": [0, 1, 1200, 14]}).json["risco"] == "baixo"
    assert c.post("/api/triagem", json={"features": [12, 7, 90000]}).json == {
        "erro": "esperadas 4 features, recebidas 3"}
    assert c.post("/api/triagem", json={"features": ["12", "sete", 0, 3]}).json == {
        "erro": "features devem ser numéricas"}
    assert c.post("/api/triagem", json={"features": [True, 1, 1, 1]}).status_code == 400
    assert c.post("/api/triagem", json={"features": [1, 1, 1, 99]}).status_code == 400
    assert c.post("/api/triagem", data="{}", content_type="text/plain").status_code == 400
    assert c.post("/api/triagem", json={}).status_code == 400
    assert c.post("/api/triagem", data='{"features":[NaN,1,1,1]}', content_type="application/json").status_code == 400
    assert mongo_db.previsoes.count_documents({}) == 2         # so as validas foram auditadas


def test_cp2_ex08_metricas_sem_acuracia(mongo_db, modelo8):
    r = e8.create_app(mongo_db, modelo8).test_client().get("/api/modelo/metricas")
    assert r.status_code == 200 and {"precisao", "recall", "f1", "matriz", "aviso"} <= set(r.json)
    assert "acuracia" not in r.json and "acurácia" in r.json["aviso"]
    assert 0 <= r.json["recall"] <= 1 and len(r.json["matriz"]) == 2


# ---------- Ex 9 ----------
def test_cp2_ex09_bloqueia_hostil_e_poupa_normal(mongo_db):
    app, cliente, feats, normal, hostil, req = e9.roteiro(mongo_db)
    assert feats[hostil][0] > 100 and feats[hostil][1] > 0.5
    assert feats[normal][0] < 2 and feats[normal][1] == 0
    assert hostil in app.bloqueados and normal not in app.bloqueados
    assert not any(ip.startswith("10.0.0.") for ip in app.bloqueados)      # fundo normal intacto
    r = req(hostil)
    assert r.status_code == 429 and r.headers["Retry-After"] == "60" and r.get_json() == {"erro": "muitas requisições"}
    assert req(normal).status_code == 200
    assert mongo_db.acessos.find_one({"ip": normal})["status"] == 200      # after_request completou


def test_cp2_ex09_populacao_pequena_nao_bloqueia():
    assert e9.detectar_anomalos({"1.1.1.1": [500, 0.9, 20], "2.2.2.2": [1, 0, 1]}) == set()


def test_cp2_ex09_piso_evita_falso_positivo():
    feats = {f"10.0.0.{i}": [1 + i * 0.1, 0.0, 2] for i in range(9)}       # todos normais e parecidos
    assert e9.detectar_anomalos(feats) == set()                            # IF marcaria ~20%; o piso impede


# ---------- Ex 10 ----------
@pytest.fixture()
def apps10(mysql_conn):
    import app_seguro
    import app_vulneravel
    import setup_banco
    from werkzeug.debug import DebuggedApplication
    servidores = []
    app_vulneravel.app.debug = True                      # o `flask run --debug` do laboratorio, sem console (evalex=False)
    for wsgi in (DebuggedApplication(app_vulneravel.app, evalex=False), app_seguro.app):
        srv = make_server("127.0.0.1", 0, wsgi, threaded=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servidores.append(srv)
    yield [f"http://127.0.0.1:{s.server_port}" for s in servidores], setup_banco
    for s in servidores:
        s.shutdown()


def test_cp2_ex10_exploit_antes_e_depois(apps10, monkeypatch):
    import exploit
    (url_vuln, url_seguro), setup = apps10
    monkeypatch.setenv("ADMIN_TOKEN", "t-admin-teste")
    monkeypatch.setenv("BAIXO_TOKEN", "t-baixo-teste")
    setup.preparar(comum.get_mysql())
    assert exploit.main(url_vuln) == 6
    setup.preparar(comum.get_mysql())
    assert exploit.main(url_seguro) == 0


def test_cp2_ex10_exploit_recusa_alvo_remoto():
    import exploit
    with pytest.raises(SystemExit):
        exploit.main("http://example.com")
