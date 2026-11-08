"""CP2 - Exercicio 9: rate limiting guiado por anomalia (A09).

Fluxo: before_request grava o acesso -> after_request completa o status -> agregacao por IP
([req_por_minuto, taxa_4xx, rotas_distintas]) -> IsolationForest(contamination=0.2, seed 42)
-> IP anomalo recebe 429 + Retry-After: 60.

Salvaguardas contra falso positivo (bloquear usuario legitimo e o custo desta abordagem):
  * so analisa com populacao minima de IPs (IsolationForest com poucos pontos e instavel);
  * so bloqueia anomalia no lado "ruim" (mais requisicoes ou mais 4xx que a mediana) e acima de
    um piso absoluto - contamination=0.2 sempre marca ~20% dos IPs, mesmo que todos sejam normais.
Comentario (2 linhas): um modelo nao-supervisionado sempre elege "os mais estranhos", entao um
pico legitimo (campanha, batch) vira 429 e derruba usuario real; regra fixa e previsivel e
auditavel, o modelo cobre o desconhecido - por isso o hibrido, o piso e o Retry-After curto.
"""
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from comum import get_mongo_db  # noqa: E402

import numpy as np  # noqa: E402
from flask import Flask, g, jsonify, request  # noqa: E402
from sklearn.ensemble import IsolationForest  # noqa: E402

JANELA_BLOQUEIO_S = 60
MIN_IPS = 6
PISO_REQ_MIN, PISO_4XX = 30.0, 0.30


def features_por_ip(col):
    """Agregacao no banco: um documento por IP com o comportamento observado."""
    pipeline = [{"$group": {
        "_id": "$ip", "n": {"$sum": 1}, "t0": {"$min": "$ts"}, "t1": {"$max": "$ts"},
        "erros": {"$sum": {"$cond": [{"$and": [{"$gte": ["$status", 400]}, {"$lt": ["$status", 500]}]}, 1, 0]}},
        "rotas": {"$addToSet": "$rota"}}}]
    resultado = {}
    for d in col.aggregate(pipeline):
        n, span = d["n"], d["t1"] - d["t0"]
        req_min = 1.0 if n < 2 else n / max(span, 1.0) * 60
        resultado[d["_id"]] = [round(req_min, 2), round(d["erros"] / n, 2), len(d["rotas"])]
    return resultado


def detectar_anomalos(feats):
    """feats: {ip: [req_min, taxa_4xx, rotas]} -> set de IPs a bloquear."""
    if len(feats) < MIN_IPS:
        return set()
    ips = sorted(feats)
    X = np.array([feats[i] for i in ips])
    marcas = IsolationForest(contamination=0.2, random_state=42).fit_predict(X)
    med_rate, med_4xx = np.median(X[:, 0]), np.median(X[:, 1])
    bloquear = set()
    for ip, marca, (rate, taxa, _) in zip(ips, marcas, X):
        lado_ruim = rate > med_rate or taxa > med_4xx
        acima_do_piso = rate >= PISO_REQ_MIN or taxa >= PISO_4XX
        if marca == -1 and lado_ruim and acima_do_piso:
            bloquear.add(ip)
    return bloquear


def create_app(db=None, relogio=time.time):
    app = Flask(__name__)
    col = (db if db is not None else get_mongo_db("cp2")).acessos
    bloqueados = {}                                   # ip -> instante em que o bloqueio expira

    def analisar():
        """Reavalia todos os IPs e (re)define os bloqueios."""
        for ip in detectar_anomalos(features_por_ip(col)):
            bloqueados[ip] = relogio() + JANELA_BLOQUEIO_S
        return dict(bloqueados)

    app.analisar = analisar
    app.bloqueados = bloqueados

    @app.before_request
    def registrar():
        ip = request.remote_addr
        agora = relogio()
        g.acesso_id = col.insert_one({
            "ip": ip, "rota": request.path, "metodo": request.method, "ts": agora,
            "timestamp": datetime.fromtimestamp(agora, timezone.utc), "status": None}).inserted_id
        if bloqueados.get(ip, 0) > agora:
            resp = jsonify({"erro": "muitas requisições"})
            resp.status_code = 429
            resp.headers["Retry-After"] = str(JANELA_BLOQUEIO_S)
            return resp

    @app.after_request
    def completar(resp):
        if getattr(g, "acesso_id", None) is not None:
            col.update_one({"_id": g.acesso_id}, {"$set": {"status": resp.status_code}})
        return resp

    @app.get("/")
    def raiz():
        return jsonify({"status": "ok"})

    @app.get("/api/dados")
    def dados():
        return jsonify({"dados": [1, 2, 3]})

    return app


def roteiro(db=None):
    """Roteiro de teste: relogio simulado (para 'espacar' requisicoes sem esperar de verdade)."""
    banco = db if db is not None else get_mongo_db("cp2")
    t = {"agora": 1_700_000_000.0}
    app = create_app(banco, relogio=lambda: t["agora"])
    cliente = app.test_client()

    def req(ip, rota="/"):
        return cliente.get(rota, environ_base={"REMOTE_ADDR": ip})

    for k in range(1, 9):                                  # populacao de fundo (comportamento normal)
        ip = f"10.0.0.{k}"
        for j in range(4 + k % 3):
            req(ip, "/" if j % 2 else "/api/dados")
            t["agora"] += 90
        if k == 3:
            req(ip, "/nao-existe")
    normal = "192.168.1.10"
    for _ in range(5):                                     # IP normal: 5 requisicoes espacadas
        assert req(normal).status_code == 200
        t["agora"] += 120
    hostil = "185.220.101.1"
    for j in range(60):                                    # IP hostil: 60 req em 10 s, 40 para rotas inexistentes
        req(hostil, f"/admin{j % 9}" if j < 40 else "/api/dados")
        t["agora"] += 10 / 60
    app.analisar()
    feats = features_por_ip(banco.acessos)
    return app, cliente, feats, normal, hostil, req


if __name__ == "__main__":
    banco = get_mongo_db("cp2")
    banco.acessos.delete_many({})
    app, cliente, feats, normal, hostil, req = roteiro(banco)
    print("=== Análise de acessos ===")
    for ip in (normal, hostil):
        r, t4, rotas = feats[ip]
        veredito = "ANOMALIA -> bloqueado" if ip in app.bloqueados else "normal"
        print(f"{ip:<15}[{r:>6.1f} req/min | 4xx {t4:.2f} | {rotas} rotas]  -> {veredito}")
    resp = req(hostil)
    print(f"Próxima requisição de {hostil} -> {resp.status_code} {resp.get_json()}\n"
          f"    Retry-After: {resp.headers.get('Retry-After')}")
    print(f"Próxima requisição de {normal} -> {req(normal).status_code}")
