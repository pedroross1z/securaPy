import ex6_1_api_usuarios as ex61
import ex6_2_analisar_senha as ex62
import ex6_3_checar_ip as ex63


def test_6_1_sequencia_do_enunciado():
    c = ex61.create_app().test_client()
    r = c.post("/api/usuarios", json={"nome": "Ana", "email": "ana@x.com", "nivel": 5})
    assert r.status_code == 201 and r.json["id"] == 1

    r = c.post("/api/usuarios", json={"nome": "Bia", "email": "ana@x.com", "nivel": 2})
    assert r.status_code == 400 and "email já existe" in r.json["erro"]

    r = c.post("/api/usuarios", json={"nome": "Cid", "email": "cid@x.com", "nivel": 9})
    assert r.status_code == 400 and "nível inválido" in r.json["erro"]

    r = c.get("/api/usuarios/1")
    assert r.status_code == 200 and r.json["nome"] == "Ana"
    assert c.get("/api/usuarios/99").status_code == 404

    r = c.put("/api/usuarios/1", json={"nivel": 3})
    assert r.status_code == 200 and r.json["nivel"] == 3
    assert c.put("/api/usuarios/1", json={"nivel": 0}).status_code == 400

    r = c.delete("/api/usuarios/1")
    assert r.status_code == 200 and r.json["mensagem"] == "Removido"
    assert c.delete("/api/usuarios/1").status_code == 404
    assert c.get("/api/usuarios").json == []


def test_6_1_corpo_invalido_e_campos_faltando():
    c = ex61.create_app().test_client()
    assert c.post("/api/usuarios", data="nao-json").status_code == 400
    assert c.post("/api/usuarios", json={"nome": "X"}).status_code == 400
    assert c.post("/api/usuarios", json={"nome": "X", "email": "x@x.com", "nivel": "5"}).status_code == 400


def test_6_2_senha_forte():
    c = ex62.create_app().test_client()
    r = c.post("/api/analisar-senha", json={"senha": "Cyber@2024"})
    assert r.status_code == 200
    assert r.json["forca"] == "Muito forte"
    assert all(r.json["criterios"].values())
    assert set(r.json["criterios"]) == {"tamanho_min", "maiuscula", "minuscula", "numero", "especial"}


def test_6_2_senha_fraca_e_erros():
    c = ex62.create_app().test_client()
    r = c.post("/api/analisar-senha", json={"senha": "abc"})
    assert r.json["forca"] == "Fraca" and r.json["criterios"]["minuscula"] is True
    r = c.post("/api/analisar-senha", json={})
    assert r.status_code == 400 and r.json == {"erro": "campo 'senha' obrigatório"}
    assert c.post("/api/analisar-senha", data="x").status_code == 400
    assert c.post("/api/analisar-senha", json={"senha": 123}).status_code == 400


def test_6_3_checar_ip():
    c = ex63.create_app().test_client()
    assert c.get("/api/checar-ip/185.220.101.1").json == {
        "ip": "185.220.101.1", "na_blacklist": True, "tipo": "publico"}
    assert c.get("/api/checar-ip/192.168.1.10").json == {
        "ip": "192.168.1.10", "na_blacklist": False, "tipo": "privado"}
    r = c.get("/api/checar-ip/999.999.1.1")
    assert r.status_code == 400 and r.json == {"erro": "IP inválido"}
    assert c.get("/api/checar-ip/abc").status_code == 400
    assert c.get("/api/checar-ip/1.2.3").status_code == 400
