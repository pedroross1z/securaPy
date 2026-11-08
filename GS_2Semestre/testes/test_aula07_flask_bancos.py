import pytest

import ex7_incidentes_mongo as ex7
import ex7_3_usuarios_mysql as ex73
import mysql.connector


# ---------- 7.1 / 7.2 - Flask + MongoDB ----------
@pytest.fixture()
def cliente(mongo_db):
    return ex7.create_app(mongo_db).test_client()


def test_7_1_sequencia_do_enunciado(cliente):
    r = cliente.post("/api/incidentes", json={
        "titulo": "Brute force SSH", "severidade": "alta", "ip_origem": "185.220.101.1"})
    assert r.status_code == 201
    id_ = r.json["id"]

    lista = cliente.get("/api/incidentes").json
    assert len(lista) == 1 and lista[0]["_id"] == id_ and lista[0]["status"] == "aberto"

    r = cliente.get("/api/incidentes/id_ruim")
    assert r.status_code == 400 and r.json["erro"] == "id inválido"

    r = cliente.put(f"/api/incidentes/{id_}", json={"status": "resolvido"})
    assert r.status_code == 200 and r.json["status"] == "resolvido"

    r = cliente.delete(f"/api/incidentes/{id_}")
    assert r.status_code == 200 and r.json["mensagem"] == "Removido"
    assert cliente.get(f"/api/incidentes/{id_}").status_code == 404


def test_7_1_validacao(cliente):
    assert cliente.post("/api/incidentes", json={"severidade": "alta"}).status_code == 400
    assert cliente.post("/api/incidentes", json={"titulo": "x", "severidade": "enorme"}).status_code == 400
    assert cliente.post("/api/incidentes", data="lixo").status_code == 400
    # id valido (ObjectId) porem inexistente
    assert cliente.get("/api/incidentes/" + "a" * 24).status_code == 404
    assert cliente.put("/api/incidentes/" + "a" * 24, json={"status": "resolvido"}).status_code == 404


def test_7_1_put_ignora_campos_fora_da_whitelist(cliente):
    id_ = cliente.post("/api/incidentes", json={"titulo": "t", "severidade": "baixa"}).json["id"]
    r = cliente.put(f"/api/incidentes/{id_}", json={"criado_em": "2000-01-01", "admin": True})
    assert r.status_code == 400                      # nada atualizavel
    assert "admin" not in cliente.get(f"/api/incidentes/{id_}").json


def test_7_2_paginacao_filtros_e_ordenacao(mongo_db, cliente):
    assert ex7.popular(mongo_db, 15) == 15

    r = cliente.get("/api/incidentes?tamanho=5&pagina=1")
    assert r.status_code == 200 and len(r.json) == 5
    assert r.headers["X-Total-Count"] == "15"
    assert r.json[0]["titulo"] == "Incidente 15"                      # mais recente primeiro
    datas = [i["criado_em"] for i in r.json]
    assert datas == sorted(datas, reverse=True)

    pag3 = cliente.get("/api/incidentes?tamanho=5&pagina=3").json
    assert [i["titulo"] for i in pag3][0] == "Incidente 05"
    assert cliente.get("/api/incidentes?tamanho=5&pagina=4").json == []

    criticos = cliente.get("/api/incidentes?severidade=critica").json
    assert criticos and all(i["severidade"] == "critica" for i in criticos)

    abertos = cliente.get("/api/incidentes?status=aberto&tamanho=3").json
    assert len(abertos) == 3 and all(i["status"] == "aberto" for i in abertos)

    combinado = cliente.get("/api/incidentes?status=aberto&severidade=alta").json
    assert all(i["status"] == "aberto" and i["severidade"] == "alta" for i in combinado)


def test_7_2_parametros_invalidos(cliente):
    assert cliente.get("/api/incidentes?pagina=abc").status_code == 400
    assert cliente.get("/api/incidentes?pagina=0").status_code == 400
    assert cliente.get("/api/incidentes?tamanho=1000").status_code == 400
    assert cliente.get("/api/incidentes?severidade=xyz").status_code == 400
    # tentativa de injecao de operador NoSQL pelo query string
    assert cliente.get("/api/incidentes?status[$ne]=x").status_code in (200, 400)
    assert cliente.get("/api/incidentes?severidade=%7B%22$ne%22:1%7D").status_code == 400


# ---------- 7.3 - Flask + MySQL ----------
@pytest.fixture()
def cliente_mysql(mysql_conn):
    ex73.garantir_tabela()
    return ex73.create_app().test_client()


def test_7_3_crud_e_erros(cliente_mysql):
    c = cliente_mysql
    r = c.post("/api/usuarios", json={"nome": "Ana", "email": "ana@x.com", "nivel_acesso": 5})
    assert r.status_code == 201
    uid = r.json["id"]

    r = c.post("/api/usuarios", json={"nome": "Outra", "email": "ana@x.com"})
    assert r.status_code == 409 and r.json == {"erro": "email já cadastrado"}

    assert c.get("/api/usuarios/999").status_code == 404
    assert c.post("/api/usuarios", json={"nome": "Sem email"}).status_code == 400
    assert c.post("/api/usuarios", data="x").status_code == 400
    assert c.post("/api/usuarios", json={"nome": "A", "email": "a@a.com", "nivel_acesso": 9}).status_code == 400

    assert c.get(f"/api/usuarios/{uid}").json["nome"] == "Ana"
    assert c.put(f"/api/usuarios/{uid}", json={"nivel_acesso": 2}).status_code == 200
    assert c.get(f"/api/usuarios/{uid}").json["nivel_acesso"] == 2
    assert c.put("/api/usuarios/999", json={"nivel_acesso": 2}).status_code == 404
    assert len(c.get("/api/usuarios").json) == 1
    assert c.delete(f"/api/usuarios/{uid}").status_code == 200
    assert c.delete(f"/api/usuarios/{uid}").status_code == 404


def test_7_3_sql_injection_no_email_e_so_texto(cliente_mysql):
    c = cliente_mysql
    r = c.post("/api/usuarios", json={"nome": "x'); DROP TABLE usuarios;--", "email": "e@e.com"})
    assert r.status_code == 201
    assert c.get("/api/usuarios").json[0]["nome"] == "x'); DROP TABLE usuarios;--"


def test_7_3_falha_de_conexao_nao_vaza_detalhes():
    def conexao_quebrada():
        raise mysql.connector.InterfaceError("2003: Can't connect to MySQL server on 'secreto:3306'")

    app = ex73.create_app(conexao_quebrada)
    r = app.test_client().get("/api/usuarios")
    assert r.status_code == 500
    assert r.json == {"erro": "serviço indisponível"}
    assert "secreto" not in r.get_data(as_text=True) and "Traceback" not in r.get_data(as_text=True)
