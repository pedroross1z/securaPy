"""CP2 - Exercicio 8: modelo de ML servido por API, com metricas auditaveis.

Features: [falhas_login, portas_distintas, bytes_saida, hora_do_dia]
  POST /api/triagem          -> {"risco": "alto"|"baixo", "confianca": 0.xx}
  GET  /api/modelo/metricas  -> precisao, recall, f1, matriz (+ aviso)

Entrada de modelo TAMBEM e entrada de usuario: so numeros finitos, 4 valores, em faixas
plausiveis; qualquer outra coisa recebe 400 e NAO e gravada em `previsoes` (A09/A08).
Os dados de treino sao SINTETICOS (gerador com seed fixa), pois nao ha base rotulada real.
"""
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from comum import get_mongo_db  # noqa: E402

import numpy as np  # noqa: E402
from flask import Flask, jsonify, request  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402
from sklearn.pipeline import Pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

N_FEATURES = 4
FAIXAS = [(0, 1e6), (0, 65535), (0, 1e12), (0, 23)]     # limites plausiveis de cada feature
NOMES = ["falhas_login", "portas_distintas", "bytes_saida", "hora_do_dia"]


def gerar_dados(n=800, seed=42):
    rnd = np.random.RandomState(seed)
    y = (rnd.rand(n) < 0.35).astype(int)
    X = np.zeros((n, N_FEATURES))
    for i, ataque in enumerate(y):
        if ataque:
            furtivo = rnd.rand() < 0.12                       # ataque "lento": parece quase normal
            X[i] = [rnd.randint(0, 4) if furtivo else rnd.randint(5, 41),
                    rnd.randint(1, 4) if furtivo else rnd.randint(3, 21),
                    rnd.lognormal(10.5, 0.8),
                    rnd.choice([0, 1, 2, 3, 4, 5, 22, 23]) if rnd.rand() < 0.7 else rnd.randint(0, 24)]
        else:
            X[i] = [rnd.randint(0, 4), rnd.randint(1, 3), rnd.lognormal(7.5, 0.9),
                    rnd.randint(7, 20) if rnd.rand() < 0.9 else rnd.randint(0, 24)]
    return X, y


def treinar(seed=42):
    X, y = gerar_dados(seed=seed)
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    modelo = Pipeline([("scaler", StandardScaler()),
                       ("clf", RandomForestClassifier(n_estimators=100, random_state=42))]).fit(X_tr, y_tr)
    pred = modelo.predict(X_te)
    metricas = {"precisao": round(float(precision_score(y_te, pred)), 2),
                "recall": round(float(recall_score(y_te, pred)), 2),
                "f1": round(float(f1_score(y_te, pred)), 2),
                "matriz": confusion_matrix(y_te, pred).tolist()}
    return modelo, metricas


def validar_features(corpo):
    """Retorna (lista_de_floats, None) ou (None, mensagem_de_erro)."""
    if not isinstance(corpo, dict) or "features" not in corpo:
        return None, "corpo JSON com 'features' obrigatório"
    f = corpo["features"]
    if not isinstance(f, list):
        return None, "'features' deve ser uma lista"
    if len(f) != N_FEATURES:
        return None, f"esperadas {N_FEATURES} features, recebidas {len(f)}"
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) for v in f):
        return None, "features devem ser numéricas"
    if any(not math.isfinite(v) for v in f):
        return None, "features devem ser finitas"
    if any(not lo <= v <= hi for v, (lo, hi) in zip(f, FAIXAS)):
        return None, "features fora das faixas plausíveis"
    return [float(v) for v in f], None


def create_app(db=None, modelo_e_metricas=None):
    app = Flask(__name__)
    col = (db if db is not None else get_mongo_db("cp2")).previsoes
    modelo, metricas = modelo_e_metricas or treinar()

    @app.post("/api/triagem")
    def triagem():
        features, erro = validar_features(request.get_json(silent=True))
        if erro:
            return jsonify({"erro": erro}), 400
        proba = modelo.predict_proba([features])[0]
        classe = int(np.argmax(proba))
        saida = {"risco": "alto" if classe == 1 else "baixo", "confianca": round(float(proba[classe]), 2)}
        col.insert_one({"entrada": dict(zip(NOMES, features)), "saida": saida,
                        "timestamp": datetime.now(timezone.utc)})
        return jsonify(saida)

    @app.get("/api/modelo/metricas")
    def get_metricas():
        return jsonify({**metricas, "aviso": (
            "A acurácia foi omitida de propósito: com classes desbalanceadas (poucos ataques) um modelo "
            "que responde sempre 'baixo' já teria acurácia alta sem detectar nada; precisão, recall e F1 "
            "da classe 'alto' mostram o que importa.")})

    @app.errorhandler(Exception)
    def erro(e):
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            return jsonify({"erro": e.name}), e.code
        app.logger.exception("falha na API de triagem")
        return jsonify({"erro": "erro interno"}), 500

    return app


if __name__ == "__main__":
    create_app().run(port=5000, debug=False)
