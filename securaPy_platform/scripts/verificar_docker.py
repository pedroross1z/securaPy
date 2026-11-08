"""Verificacao via Docker SDK (Modulo F): os 3 servicos do compose estao 'running'?

    python scripts/verificar_docker.py [url_da_api]
Saida != 0 se algum servico nao estiver rodando (util em CI).
"""
import sys

import docker
import requests

ESPERADOS = ["securapy_api", "securapy_mongo", "securapy_mysql"]


def status(client=None, nomes=ESPERADOS):
    client = client or docker.from_env()
    resultado = {}
    for nome in nomes:
        try:
            c = client.containers.get(nome)
            c.reload()
            saude = (c.attrs.get("State", {}).get("Health") or {}).get("Status", "-")
            resultado[nome] = (c.status, saude)
        except docker.errors.NotFound:
            resultado[nome] = ("ausente", "-")
    return resultado


def main(url_api=None):
    try:
        res = status()
    except docker.errors.DockerException as e:
        print(f"Erro: não foi possível falar com o Docker ({e})")
        return 2
    print(f"{'CONTÊINER':<18}{'STATUS':<10}SAÚDE")
    for nome, (st, saude) in res.items():
        print(f"{nome:<18}{st:<10}{saude}  {'OK' if st == 'running' else '<- PROBLEMA'}")
    ok = all(st == "running" for st, _ in res.values())
    if url_api and ok:
        try:
            r = requests.get(f"{url_api}/api/health", timeout=5)
            print(f"GET {url_api}/api/health -> {r.status_code} {r.json()}")
            ok = ok and r.status_code == 200
        except requests.RequestException as e:
            print(f"API não respondeu: {type(e).__name__}")
            ok = False
    print("=== TUDO CERTO ===" if ok else "=== HÁ PROBLEMAS ===")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else None))
