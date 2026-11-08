"""Modulo D - API REST (cenarios D1-D5) + tratamento de erros + bonus JWT."""
import time

import jwt
import pytest

from api.auth import ALGORITMO, TokenInvalido, emitir_token, verificar_token


# ------------------------------------------------------------------ cenarios do enunciado
def test_d1_alertas_filtrados_e_paginados(client, analisado):
    r = client.get("/api/alertas?severidade=critica&pagina=1&tamanho=5")
    assert r.status_code == 200
    assert r.json["itens"] and len(r.json["itens"]) <= 5
    assert all(a["severidade"] == "CRITICA" for a in r.json["itens"])
    assert r.json["pagina"] == 1 and r.json["tamanho"] == 5 and r.json["total"] >= len(r.json["itens"])
    pag2 = client.get("/api/alertas?tamanho=5&pagina=2").json["itens"]
    assert pag2 and {a["id"] for a in pag2}.isdisjoint({a["id"] for a in client.get("/api/alertas?tamanho=5").json["itens"]})


def test_d2_busca_por_ip_traz_tudo(client, analisado):
    r = client.get("/api/ip/185.220.101.1")
    assert r.status_code == 200
    d = r.json
    assert len(d["eventos"]) == 25 and d["alertas"] and d["na_blacklist"] is True
    assert d["geolocalizacao"]["cidade"] == "Berlin"
    assert d["score_ml"]["nivel"] == "ALTO"
    assert d["explicacao"]["rotulo"] in ("SUSPEITO", "CRITICO")


def test_d3_post_alertas_sem_token_401(client):
    r = client.post("/api/alertas", json={"regra_nome": "x", "severidade": "ALTA", "ip": "1.2.3.4"})
    assert r.status_code == 401 and r.headers["WWW-Authenticate"] == "Bearer"


def test_d4_post_alertas_corpo_invalido_400(client, auth):
    for corpo in [{}, {"regra_nome": "x"}, {"regra_nome": "x", "severidade": "ENORME", "ip": "1.2.3.4"},
                  {"regra_nome": "x", "severidade": "ALTA", "ip": "999.1.1.1"},
                  {"regra_nome": "", "severidade": "ALTA", "ip": "1.2.3.4"},
                  {"regra_nome": "x" * 500, "severidade": "ALTA", "ip": "1.2.3.4"}]:
        assert client.post("/api/alertas", json=corpo, headers=auth).status_code == 400, corpo
    assert client.post("/api/alertas", data="nao-json", headers=auth).status_code == 400
    ok = client.post("/api/alertas", json={"regra_nome": "Manual", "severidade": "alta", "ip": "1.2.3.4"}, headers=auth)
    assert ok.status_code == 201
    assert client.get(f"/api/alertas/{ok.json['id']}").json["origem"] == "manual"


def test_d5_ip_malformado_400_amigavel(client):
    for ip in ("999.999.1.1", "abc", "1.2.3", "1.2.3.4.5", "%27%20OR%201=1"):
        r = client.get(f"/api/ip/{ip}")
        assert r.status_code == 400 and r.json == {"erro": "IP inválido"}, ip


# ------------------------------------------------------------------ demais rotas e regras
def test_alerta_por_id_invalido_inexistente_e_valido(client, analisado):
    assert client.get("/api/alertas/xyz").status_code == 400
    assert client.get("/api/alertas/" + "a" * 24).status_code == 404
    alerta = client.get("/api/alertas").json["itens"][0]
    assert client.get(f"/api/alertas/{alerta['id']}").json["id"] == alerta["id"]


def test_eventos_com_filtros_e_validacao(client, analisado):
    r = client.get("/api/eventos?fonte=auth&tipo=fail&ip=185.220.101.1&tamanho=100")
    assert r.status_code == 200 and r.json["total"] == 11
    assert client.get("/api/eventos?tamanho=1000").json["tamanho"] == 100         # teto do servidor
    for q in ("pagina=0", "pagina=abc", "tamanho=-1", "fonte=ldap", "ip=1.1.1", "desde=ontem", "tipo=FAIL;DROP"):
        assert client.get(f"/api/eventos?{q}").status_code == 400, q
    assert client.get("/api/eventos?desde=2025-02-20&ate=2025-02-20 08:16:00").status_code == 200


def test_analisar_exige_token_e_valida_caminho(client, auth, auth_baixo):
    assert client.post("/api/analisar", json={}).status_code == 401
    assert client.post("/api/analisar", json={"caminho": "../.."}, headers=auth).status_code == 400
    assert client.post("/api/analisar", json={"caminho": "/etc"}, headers=auth).status_code == 400
    assert client.post("/api/analisar", json={"caminho": "nao_existe"}, headers=auth).status_code == 404
    assert client.post("/api/analisar", json={"caminho": 5}, headers=auth).status_code == 400
    assert client.post("/api/analisar", json={}, headers=auth_baixo).status_code == 200      # nivel 1 pode analisar


def test_analisar_lote_de_eventos_e_validacao(client, auth):
    ev = {"timestamp": "2025-02-20 08:15:01", "fonte": "auth", "tipo": "FAIL",
          "ip": "6.6.6.6", "detalhes": "usuario=root"}
    r = client.post("/api/analisar", json={"eventos": [dict(ev) for _ in range(6)]}, headers=auth)
    assert r.status_code == 200 and r.json["eventos_persistidos"] == 6
    assert any(a["ip"] == "6.6.6.6" for a in r.json["ameacas"])
    for ruim in ([], "x", [1], [{**ev, "fonte": "ldap"}], [{**ev, "timestamp": "ontem"}], [{**ev, "ip": "x"}],
                 [{k: v for k, v in ev.items() if k != "tipo"}], [ev] * 5001):
        assert client.post("/api/analisar", json={"eventos": ruim}, headers=auth).status_code == 400


def test_analise_resumo_e_idempotente(client, auth, analisado):
    assert analisado["eventos_persistidos"] == 58 and analisado["alertas_criticos"] > 0
    assert analisado["ranking_risco"][-1]["rotulo"] == "normal"
    assert analisado["correlacao_temporal"]
    assert client.post("/api/analisar", json={}, headers=auth).json["eventos_persistidos"] == 58
    assert client.get("/api/resumo").json["total_eventos"] == 58                         # nao duplicou


def test_relatorio_exportavel(client, analisado):
    r = client.get("/api/relatorio")
    assert r.status_code == 200
    assert {"resumo", "alertas_recentes", "ranking_risco", "total_alertas"} <= set(r.json)


def test_leitura_protegida_por_configuracao(plataforma):
    from api.app import create_app
    plataforma.settings.exigir_auth_leitura = True
    c = create_app(plataforma).test_client()
    assert c.get("/api/alertas").status_code == 401
    assert c.get("/api/health").status_code == 200                                       # health continua publico


def test_usuarios_admin_crud_e_permissoes(client, auth, auth_baixo):
    assert client.get("/api/usuarios", headers=auth_baixo).status_code == 403
    assert client.get("/api/usuarios").status_code == 401
    novo = {"nome": "Bia", "email": "bia@x.com", "senha": "Senha@12345", "nivel_acesso": 3}
    assert client.post("/api/usuarios", json=novo, headers=auth).status_code == 201
    assert client.post("/api/usuarios", json=novo, headers=auth).status_code == 409
    assert client.post("/api/usuarios", json={**novo, "email": "c@x.com", "nivel_acesso": 9}, headers=auth).status_code == 400
    assert client.put("/api/usuarios/bia@x.com", json={"nivel_acesso": 4}, headers=auth).status_code == 200
    assert client.put("/api/usuarios/zzz@x.com", json={"nivel_acesso": 4}, headers=auth).status_code == 404
    assert "senha_hash" not in client.get("/api/usuarios", headers=auth).get_data(as_text=True)
    assert client.delete("/api/usuarios/admin@x.com", headers=auth).status_code == 400   # nao se auto-remove
    assert client.delete("/api/usuarios/bia@x.com", headers=auth).status_code == 200


# ------------------------------------------------------------------ login e JWT (bonus)
def test_login_generico_e_limite_de_tentativas(client):
    a = client.post("/api/login", json={"email": "admin@x.com", "senha": "errada"})
    b = client.post("/api/login", json={"email": "fantasma@x.com", "senha": "errada"})
    assert a.status_code == b.status_code == 401 and a.json == b.json == {"erro": "Credenciais inválidas"}
    assert client.post("/api/login", json={"email": "admin@x.com"}).status_code == 400
    assert client.post("/api/login", json={"email": "' OR '1'='1", "senha": "x"}).status_code == 401
    for _ in range(5):
        client.post("/api/login", json={"email": "ana@x.com", "senha": "errada"})
    r = client.post("/api/login", json={"email": "ana@x.com", "senha": "Senha@12345"})
    assert r.status_code == 429 and r.headers["Retry-After"]


def test_jwt_emissao_verificacao_e_ataques(settings):
    usuario = {"id": 1, "email": "a@x.com", "nivel_acesso": 5}
    token, exp = emitir_token(settings, usuario)
    assert verificar_token(settings, token) == {"email": "a@x.com", "id": 1, "nivel_acesso": 5}
    expirado, _ = emitir_token(settings, usuario, agora=time.time() - 7200)
    sem_assinatura = jwt.encode({"sub": "a@x.com", "nivel": 5, "exp": exp, "iat": 1, "iss": "securapy"}, None,
                                algorithm="none")
    outra_chave = jwt.encode({"sub": "a@x.com", "nivel": 5, "exp": exp, "iat": 1, "iss": "securapy"},
                             "k" * 40, algorithm=ALGORITMO)
    sem_issuer = jwt.encode({"sub": "a@x.com", "nivel": 5, "exp": exp, "iat": 1}, settings.jwt_secret,
                            algorithm=ALGORITMO)
    for ruim in (expirado, sem_assinatura, outra_chave, sem_issuer, "lixo", token[:-3] + "abc", ""):
        with pytest.raises(TokenInvalido):
            verificar_token(settings, ruim)


def test_token_forjado_nao_da_acesso(client, settings):
    forjado = jwt.encode({"sub": "x@x.com", "nivel": 5, "iat": 1, "exp": int(time.time()) + 999, "iss": "securapy"},
                         "chave-errada-" + "x" * 30, algorithm=ALGORITMO)
    r = client.post("/api/alertas", json={"regra_nome": "x", "severidade": "ALTA", "ip": "1.2.3.4"},
                    headers={"Authorization": f"Bearer {forjado}"})
    assert r.status_code == 401


# ------------------------------------------------------------------ erros sem vazar detalhes
def test_erros_json_sem_traceback(client, plataforma, monkeypatch):
    assert client.get("/api/nao-existe").status_code == 404
    assert client.get("/api/nao-existe").json == {"erro": "rota não existe"}
    assert client.delete("/api/eventos").status_code == 405

    def boom(*a, **k):
        raise RuntimeError("SEGREDO senha=hunter2 SELECT * FROM x")
    monkeypatch.setattr(plataforma.mongo, "buscar_eventos", boom)
    r = client.get("/api/eventos")
    corpo = r.get_data(as_text=True)
    assert r.status_code == 500 and r.json == {"erro": "erro interno"}
    assert "hunter2" not in corpo and "SELECT" not in corpo and "Traceback" not in corpo


def test_dependencia_fora_do_ar_vira_503(client, plataforma, monkeypatch):
    from db.mongo_repo import RepositorioIndisponivel

    def fora(*a, **k):
        raise RepositorioIndisponivel("ServerSelectionTimeoutError")
    monkeypatch.setattr(plataforma.mongo, "buscar_alertas", fora)
    r = client.get("/api/alertas")
    assert r.status_code == 503 and "ServerSelection" not in r.get_data(as_text=True)
    assert r.headers["Retry-After"]


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json["status"] == "ok" and r.json["mongo"] and r.json["mysql"]
