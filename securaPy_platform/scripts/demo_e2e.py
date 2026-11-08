"""Teste ponta a ponta contra a plataforma no ar (docker compose up):
login -> analisar -> dashboard -> busca por IP -> alertas em tempo real em 2 consoles -> relatorio JSON.

    python scripts/demo_e2e.py [http://127.0.0.1:5000]
Credenciais: ADMIN_EMAIL / ADMIN_PASSWORD do .env. Grava saida/relatorio_exemplo.json.
"""
import json
import socket
import sys
import time
from pathlib import Path

import requests

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
from settings import carregar_env  # noqa: E402

carregar_env()
import os  # noqa: E402


def abrir_console(host, porta):
    c = socket.create_connection((host, porta), timeout=5)
    c.recv(1024)                                   # banner de boas-vindas
    c.settimeout(5)
    return c


def ler_alertas(console, esperado=1, prazo=6):
    console.settimeout(1)
    recebido, fim = "", time.time() + prazo
    while time.time() < fim and recebido.count("\n") < esperado:
        try:
            recebido += console.recv(4096).decode()
        except socket.timeout:
            pass
    return [l for l in recebido.splitlines() if l.strip()]


def main(base="http://127.0.0.1:5000"):
    host = base.split("//")[1].split(":")[0]
    print(f"== 1. saúde: {requests.get(base + '/api/health', timeout=10).json()}")

    r = requests.post(base + "/api/login", json={"email": os.environ["ADMIN_EMAIL"],
                                                  "senha": os.environ["ADMIN_PASSWORD"]}, timeout=10)
    r.raise_for_status()
    auth = {"Authorization": f"Bearer {r.json()['token']}"}
    print("== 2. login OK (JWT, expira em", r.json()["expira_em"], ")")

    print("== 3. sem token: POST /api/alertas ->",
          requests.post(base + "/api/alertas", json={}, timeout=10).status_code)

    consoles = [abrir_console(host, 9999) for _ in range(2)]
    print("== 4. dois consoles conectados ao servidor de alertas (porta 9999)")

    r = requests.post(base + "/api/analisar", json={}, headers=auth, timeout=60)
    r.raise_for_status()
    resumo = r.json()
    print(f"== 5. análise: {resumo['eventos_persistidos']} eventos, "
          f"{resumo['alertas_regras'] + resumo['alertas_deteccao']} alertas, {resumo['alertas_criticos']} críticos")
    for item in resumo["ranking_risco"][:4]:
        print(f"      {item['ip']:<16} score {item['score']:.2f}  {item['nivel']:<6} {item['rotulo']}")

    for i, console in enumerate(consoles, 1):
        linhas = ler_alertas(console, esperado=3)
        print(f"== 6. console {i} recebeu {len(linhas)} alertas em tempo real; ex.: {linhas[0] if linhas else '-'}")

    d = requests.get(base + "/api/ip/185.220.101.1", timeout=30).json()
    print(f"== 7. /api/ip/185.220.101.1: {len(d['eventos'])} eventos, {len(d['alertas'])} alertas, "
          f"geo={d['geolocalizacao'].get('cidade')}, ML={d['score_ml']['nivel']}, "
          f"LLM={d['explicacao']['rotulo']} ({d['explicacao']['origem']})")

    s = requests.Session()
    html = s.get(base + "/login", timeout=10).text
    token = html.split('name="csrf" value="')[1].split('"')[0]
    s.post(base + "/login", data={"csrf": token, "email": os.environ["ADMIN_EMAIL"],
                                  "senha": os.environ["ADMIN_PASSWORD"]}, timeout=10)
    dash = s.get(base + "/dashboard", timeout=10)
    print(f"== 8. dashboard: HTTP {dash.status_code}, {len(dash.text)} bytes; headers de segurança: "
          f"{[h for h in ('X-Content-Type-Options', 'X-Frame-Options', 'Content-Security-Policy') if h in dash.headers]}")

    rel = requests.get(base + "/api/relatorio", timeout=30).json()
    destino = RAIZ / "saida" / "relatorio_exemplo.json"
    destino.parent.mkdir(exist_ok=True)
    destino.write_text(json.dumps(rel, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"== 9. relatório exportado em {destino}")
    for c in consoles:
        c.close()


if __name__ == "__main__":
    main(*(sys.argv[1:2]))
