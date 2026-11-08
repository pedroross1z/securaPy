"""Exercicio 10.1 - Cliente da API do NVD (National Vulnerability Database).

Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228

Observacao: para uma CVE que nao existe o NVD costuma responder 200 com
totalResults = 0 (e nao 404); o codigo trata os dois casos.
Chave opcional (limites maiores): variavel de ambiente NVD_API_KEY.
"""
import os
import re
import sys
import time

import requests

URL_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PADRAO_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class ErroNVD(Exception):
    """Falha de comunicacao com o NVD (timeout, conexao, rate limit, 5xx)."""


def _cvss(metricas):
    """Escolhe a melhor metrica disponivel: v4.0 > v3.1 > v3.0 > v2."""
    for chave in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        itens = metricas.get(chave)
        if itens:
            dados = itens[0]["cvssData"]
            severidade = dados.get("baseSeverity") or itens[0].get("baseSeverity", "N/D")
            return dados["baseScore"], severidade, dados.get("version", "?")
    return None, "N/D", None


def buscar_cve(cve_id, get=requests.get, tentativas=3, dormir=time.sleep):
    """Retorna dict {id, descricao, cvss, severidade, versao_cvss} ou None se nao existir."""
    cve_id = cve_id.strip().upper()
    if not PADRAO_CVE.match(cve_id):
        raise ValueError(f"Formato de CVE inválido: {cve_id!r}")

    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    resp = None
    for i in range(tentativas):
        try:
            resp = get(URL_NVD, params={"cveId": cve_id}, headers=headers, timeout=30)
        except requests.exceptions.Timeout:
            raise ErroNVD("Timeout ao consultar o NVD") from None
        except requests.exceptions.ConnectionError:
            raise ErroNVD("Falha de conexão com o NVD") from None
        if resp.status_code in (403, 429, 503):          # limite de taxa / indisponivel
            dormir(2 ** i)                               # backoff exponencial
            continue
        break
    else:
        raise ErroNVD(f"NVD recusou a requisição (HTTP {resp.status_code}) — tente mais tarde")

    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise ErroNVD(f"NVD respondeu HTTP {resp.status_code}")
    try:
        vulns = resp.json().get("vulnerabilities", [])
    except ValueError:
        raise ErroNVD("Resposta do NVD não é JSON válido") from None
    if not vulns:
        return None

    cve = vulns[0]["cve"]
    descricao = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                     "(sem descrição)")
    score, severidade, versao = _cvss(cve.get("metrics", {}))
    return {"id": cve["id"], "descricao": descricao, "cvss": score,
            "severidade": severidade, "versao_cvss": versao}


def exibir(cve):
    print(cve["id"])
    score = "N/D" if cve["cvss"] is None else f"{cve['cvss']:.1f}"
    print(f"  CVSS: {score} ({cve['severidade']})")
    print(f"  Descrição: {cve['descricao']}")


def main(argv):
    ids = argv or ["CVE-2021-44228", "CVE-1999-0000"]
    for cve_id in ids:
        try:
            cve = buscar_cve(cve_id)
        except ValueError as e:
            print(f"{cve_id}: {e}")
        except ErroNVD as e:
            print(f"{cve_id}: erro — {e}")
        else:
            exibir(cve) if cve else print(f"{cve_id}\n  CVE não encontrada")


if __name__ == "__main__":
    main(sys.argv[1:])
