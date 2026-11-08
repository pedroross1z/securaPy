"""Modulo E - dashboard e seguranca web (cenarios E1-E4)."""
import logging
import re

import pytest

XSS = "<script>alert(1)</script>"


def csrf_de(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def entrar(c, email="admin@x.com", senha="Senha@12345"):
    token = csrf_de(c.get("/login").get_data(as_text=True))
    return c.post("/login", data={"csrf": token, "email": email, "senha": senha})


@pytest.fixture()
def logado(client):
    r = entrar(client)
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
    return client


def test_e1_xss_na_descricao_aparece_como_texto(logado):
    pagina = logado.get("/dashboard").get_data(as_text=True)
    r = logado.post("/alertas", data={"csrf": csrf_de(pagina), "regra_nome": "Teste", "severidade": "ALTA",
                                      "ip": "1.2.3.4", "descricao": XSS})
    assert r.status_code == 302
    html = logado.get("/dashboard").get_data(as_text=True)
    assert XSS not in html and "<script>alert" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html            # texto literal na tela
    assert "<script" not in html                                       # a pagina nao tem NENHUM script


def test_e1_xss_tambem_no_nome_da_regra_e_na_pagina_do_ip(logado):
    token = csrf_de(logado.get("/dashboard").get_data(as_text=True))
    logado.post("/alertas", data={"csrf": token, "regra_nome": '"><img src=x onerror=alert(1)>',
                                  "severidade": "ALTA", "ip": "1.2.3.4", "descricao": "d"})
    for rota in ("/dashboard", "/ip/1.2.3.4"):
        html = logado.get(rota).get_data(as_text=True)
        assert "<img src=x" not in html and "&#34;&gt;&lt;img" in html


def test_e2_headers_de_seguranca_em_todas_as_respostas(client):
    for rota, metodo in (("/login", "get"), ("/dashboard", "get"), ("/api/health", "get"),
                         ("/nao-existe", "get"), ("/api/nao-existe", "get"), ("/static/style.css", "get")):
        r = getattr(client, metodo)(rota)
        assert r.headers["X-Content-Type-Options"] == "nosniff", rota
        assert r.headers["X-Frame-Options"] == "DENY", rota
        assert r.headers["Content-Security-Policy"] == "default-src 'self'", rota


def test_e3_login_mensagem_generica(client):
    a = entrar(client, "admin@x.com", "errada")
    b = entrar(client, "fantasma@x.com", "errada")
    assert a.status_code == b.status_code == 401
    ta, tb = a.get_data(as_text=True), b.get_data(as_text=True)
    assert "Credenciais inválidas." in ta and "Credenciais inválidas." in tb
    assert "não existe" not in ta + tb and "senha incorreta" not in (ta + tb).lower()


def test_e3_login_campos_vazios_csrf_e_limite(client):
    token = csrf_de(client.get("/login").get_data(as_text=True))
    assert client.post("/login", data={"csrf": token, "email": "", "senha": ""}).status_code == 400
    assert client.post("/login", data={"email": "admin@x.com", "senha": "Senha@12345"}).status_code == 400   # sem CSRF
    assert client.post("/login", data={"csrf": "forjado", "email": "admin@x.com", "senha": "Senha@12345"}).status_code == 400
    for _ in range(5):
        entrar(client, "ana@x.com", "errada")
    assert entrar(client, "ana@x.com", "Senha@12345").status_code == 429


def test_e3_sqli_no_formulario_de_login(client):
    assert entrar(client, "' OR '1'='1", "' OR '1'='1").status_code == 401


def test_e4_cada_requisicao_gera_linha_de_log(client, caplog):
    with caplog.at_level(logging.INFO, logger="securapy.acesso"):
        client.get("/login")
        client.get("/api/health")
        client.get("/rota-que-nao-existe")
    linhas = [r.getMessage() for r in caplog.records if r.name == "securapy.acesso"]
    assert any("GET /login 200" in l for l in linhas)
    assert any("GET /api/health 200" in l for l in linhas)
    assert any("GET /rota-que-nao-existe 404" in l for l in linhas)


def test_e4_falha_de_login_e_registrada(client, caplog):
    with caplog.at_level(logging.WARNING, logger="securapy"):
        entrar(client, "admin@x.com", "errada")
    assert any("login web falhou" in r.getMessage() for r in caplog.records)
    assert not any("errada" in r.getMessage() for r in caplog.records)      # senha nunca no log


def test_rotas_exigem_login_e_logout_exige_csrf(client):
    for rota in ("/dashboard", "/ip/1.2.3.4", "/ip?q=1.2.3.4"):
        r = client.get(rota)
        assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert client.post("/alertas", data={}).status_code == 302
    entrar(client)
    assert client.post("/logout", data={}).status_code == 400
    token = csrf_de(client.get("/dashboard").get_data(as_text=True))
    assert client.post("/logout", data={"csrf": token}).status_code == 302
    assert client.get("/dashboard").status_code == 302


def test_cookie_de_sessao_httponly_e_samesite(client):
    token = csrf_de(client.get("/login").get_data(as_text=True))
    r = client.post("/login", data={"csrf": token, "email": "admin@x.com", "senha": "Senha@12345"})
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_dashboard_completo_apos_analise(logado):
    token = csrf_de(logado.get("/dashboard").get_data(as_text=True))
    logado.post("/analisar", data={"csrf": token})
    html = logado.get("/dashboard").get_data(as_text=True)
    assert "185.220.101.1" in html and "CRITICA" in html and "auth" in html and "firewall" in html
    assert logado.get("/ip?q=185.220.101.1").headers["Location"].endswith("/ip/185.220.101.1")
    pagina = logado.get("/ip/185.220.101.1").get_data(as_text=True)
    assert "Berlin" in pagina and "Assistente" in pagina and "blacklist" in pagina
    assert logado.get("/ip/999.1.1.1").status_code == 400
    assert logado.get("/ip?q=xyz").status_code == 302                       # volta ao dashboard com aviso


def test_alerta_invalido_pelo_formulario_nao_e_gravado(logado, plataforma):
    token = csrf_de(logado.get("/dashboard").get_data(as_text=True))
    logado.post("/alertas", data={"csrf": token, "regra_nome": "x", "severidade": "ALTA", "ip": "nao-ip",
                                  "descricao": "d"})
    assert plataforma.mongo.buscar_alertas()[1] == 0
