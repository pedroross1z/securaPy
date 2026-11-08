from types import SimpleNamespace

import pytest
import requests

import ex10_1_nvd as nvd
import ex10_2_github as gh
import ex10_3_enriquecedor as enr


def resp(status=200, json=None, headers=None):
    def _json():
        if json is None:
            raise ValueError("sem json")
        return json
    return SimpleNamespace(status_code=status, json=_json, headers=headers or {}, reason="OK")


# ---------- 10.1 NVD ----------
LOG4SHELL = {"vulnerabilities": [{"cve": {
    "id": "CVE-2021-44228",
    "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "Apache Log4j2 RCE"}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL",
                                                 "version": "3.1"}}]}}}]}


def test_nvd_extrai_descricao_cvss_e_severidade():
    r = nvd.buscar_cve("cve-2021-44228", get=lambda *a, **k: resp(json=LOG4SHELL))
    assert r == {"id": "CVE-2021-44228", "descricao": "Apache Log4j2 RCE", "cvss": 10.0,
                 "severidade": "CRITICAL", "versao_cvss": "3.1"}


def test_nvd_cve_inexistente_404_e_lista_vazia():
    assert nvd.buscar_cve("CVE-1999-0000", get=lambda *a, **k: resp(404)) is None
    assert nvd.buscar_cve("CVE-1999-0000", get=lambda *a, **k: resp(json={"vulnerabilities": []})) is None


def test_nvd_timeout_e_conexao():
    def timeout(*a, **k):
        raise requests.exceptions.Timeout()

    def conexao(*a, **k):
        raise requests.exceptions.ConnectionError()
    with pytest.raises(nvd.ErroNVD, match="Timeout"):
        nvd.buscar_cve("CVE-2021-44228", get=timeout)
    with pytest.raises(nvd.ErroNVD, match="conexão"):
        nvd.buscar_cve("CVE-2021-44228", get=conexao)


def test_nvd_rate_limit_faz_backoff_e_depois_desiste():
    esperas = []
    respostas = iter([resp(429), resp(429), resp(json=LOG4SHELL)])
    r = nvd.buscar_cve("CVE-2021-44228", get=lambda *a, **k: next(respostas), dormir=esperas.append)
    assert r["cvss"] == 10.0 and esperas == [1, 2]
    with pytest.raises(nvd.ErroNVD, match="recusou"):
        nvd.buscar_cve("CVE-2021-44228", get=lambda *a, **k: resp(429), dormir=lambda s: None)


def test_nvd_rejeita_id_malformado_antes_de_chamar_a_api():
    chamadas = []
    with pytest.raises(ValueError):
        nvd.buscar_cve("CVE-2021-44228&x=1", get=lambda *a, **k: chamadas.append(1))
    assert chamadas == []


# ---------- 10.2 GitHub ----------
def test_github_pagina_ate_esvaziar_e_ordena_por_estrelas():
    paginas = {1: [{"name": f"r{i}", "stargazers_count": i} for i in range(100)],
               2: [{"name": "top", "stargazers_count": 999}], 3: []}

    def get(url, params=None, **k):
        return resp(json=paginas[params["page"]])
    repos = gh.listar_repos("torvalds", get=get)
    assert len(repos) == 101 and repos[0]["name"] == "top"


@pytest.mark.parametrize("status,trecho", [(404, "404"), (403, "Limite"), (429, "Limite"), (500, "500")])
def test_github_erros_http(status, trecho):
    with pytest.raises(gh.ErroGitHub, match=trecho):
        gh.buscar_usuario("octocat", get=lambda *a, **k: resp(status))


def test_github_timeout_conexao_e_nome_invalido():
    def t(*a, **k):
        raise requests.exceptions.Timeout()
    with pytest.raises(gh.ErroGitHub, match="Tempo"):
        gh.buscar_usuario("octocat", get=t)
    with pytest.raises(gh.ErroGitHub, match="inválido"):
        gh.buscar_usuario("../../etc", get=t)


def test_github_salvar_json(tmp_path):
    caminho = gh.salvar_json("torvalds", {"a": 1}, pasta=tmp_path)
    assert caminho.name == "github_torvalds.json" and '"a": 1' in caminho.read_text()


# ---------- 10.3 Enriquecedor ----------
def api_ok(url, **k):
    ip = url.split("/")[-2]
    return resp(json={"ip": ip, "city": "Cidade", "country": "XX", "org": "Org"})


def test_enriquecedor_cenario_do_enunciado():
    e = enr.Enriquecedor(get=api_ok)
    saida = e.relatorio(["8.8.8.8", "1.1.1.1", "185.220.101.1", "192.168.1.10", "8.8.8.8"])
    assert (e.consultas_http, e.cache_hits, e.internos) == (3, 1, 1)
    assert "[CACHE] sem nova chamada HTTP" in saida
    assert "Rede Interna (não consultado)" in saida
    assert "EXTERNO, suspeito" in saida
    assert saida.splitlines()[-1] == "=== Resumo === Consultas HTTP: 3 | Cache hits: 1 | Internos: 1"


def test_enriquecedor_backoff_429_e_falha_nao_envenena_cache():
    esperas, estado = [], {"n": 0}

    def get(url, **k):
        estado["n"] += 1
        return resp(429) if estado["n"] <= 3 else api_ok(url)
    e = enr.Enriquecedor(get=get, dormir=esperas.append)
    assert e.enriquecer("8.8.8.8")["origem"] == "FALHA"
    assert esperas == [1, 2] and "8.8.8.8" not in e.cache      # falha nao foi cacheada
    assert e.enriquecer("8.8.8.8")["origem"] == "API"           # tentativa seguinte funciona


def test_enriquecedor_timeout_ip_invalido():
    def t(*a, **k):
        raise requests.exceptions.Timeout()
    e = enr.Enriquecedor(get=t)
    assert e.enriquecer("8.8.8.8")["origem"] == "FALHA" and not e.cache
    assert e.enriquecer("999.1.1.1")["origem"] == "FALHA"
