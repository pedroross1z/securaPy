"""CP1 - Exercicio 10 (desafio): mini-pipeline SIEM  log -> MongoDB -> ML.

1. le o auth.log do SecuraPy (coletor do 1o semestre) e normaliza em documentos;
2. insere no MongoDB;
3. conta FAILs por IP via AGREGACAO (no banco, nao em laco Python);
4. monta o dataset [qtd_fails] e rotula suspeito=1 se >= 5 falhas;
5. treina um classificador e preve um IP novo com 8 falhas.
"""
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from comum import LOGS_DIR, get_mongo_db  # noqa: E402

import coletor  # noqa: E402  (SecuraPy 1o semestre)
from sklearn.tree import DecisionTreeClassifier  # noqa: E402

LIMITE_SUSPEITO = 5


def ingerir(col, caminho=LOGS_DIR / "auth.log"):
    eventos = coletor.carregar_log(str(caminho), "auth")
    docs = [{**e, "timestamp": datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S")} for e in eventos]
    if docs:
        col.insert_many(docs)
    return len(docs)


def fails_por_ip(col):
    """Todos os IPs vistos (inclusive os que so tiveram OK, com 0 falhas)."""
    pipeline = [
        {"$group": {"_id": "$ip",
                    "fails": {"$sum": {"$cond": [{"$eq": ["$tipo", "FAIL"]}, 1, 0]}}}},
        {"$sort": {"fails": -1, "_id": 1}},
    ]
    return [(d["_id"], d["fails"]) for d in col.aggregate(pipeline)]


def montar_dataset(contagens):
    X = [[f] for _, f in contagens]
    y = [1 if f >= LIMITE_SUSPEITO else 0 for _, f in contagens]
    return X, y


def treinar_e_prever(X, y, fails_novo=8):
    modelo = DecisionTreeClassifier(random_state=42).fit(X, y)
    return int(modelo.predict([[fails_novo]])[0])


if __name__ == "__main__":
    col = get_mongo_db("cp1")["auth_eventos"]
    col.drop()
    print(f"Eventos inseridos no MongoDB: {ingerir(col)}")
    contagens = fails_por_ip(col)
    for ip, f in contagens:
        print(f"{ip} -> {f} FAILs (suspeito={int(f >= LIMITE_SUSPEITO)})")
    X, y = montar_dataset(contagens)
    print(f"Dataset de treino: {X} rótulos {y}")
    print("Previsão para IP com 8 falhas ->", "Suspeito (1)" if treinar_e_prever(X, y) else "Normal (0)")
