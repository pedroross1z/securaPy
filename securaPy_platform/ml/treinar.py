"""Treino do classificador de risco (Modulo C).

    python -m ml.treinar

Pipeline (StandardScaler + RandomForest) -> validacao cruzada -> metricas no conjunto de teste ->
joblib + hash SHA-256 do arquivo + relatorio de metricas (JSON).
"""
import json
import sys
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from core.integridade import calcular_hash_arquivo
from ml.dados_treino import gerar_dataset

PASTA = Path(__file__).resolve().parent
MODELO = PASTA / "modelo.pkl"


def caminhos(pasta=PASTA):
    pasta = Path(pasta)
    return pasta / "modelo.pkl", pasta / "modelo.pkl.sha256", pasta / "metricas.json"


def criar_pipeline():
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(n_estimators=150, random_state=42, class_weight="balanced")),
    ])


def treinar(seed=42):
    """Treina e avalia. Retorna (modelo_treinado_no_treino, relatorio_dict)."""
    X, y = gerar_dataset(seed=seed)
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_validate(criar_pipeline(), X_tr, y_tr, cv=cv,
                            scoring=("precision", "recall", "f1"))
    modelo = criar_pipeline().fit(X_tr, y_tr)
    pred = modelo.predict(X_te)
    relatorio = {
        "amostras_treino": int(len(y_tr)), "amostras_teste": int(len(y_te)),
        "validacao_cruzada_5_folds": {
            m: {"media": round(float(scores[f"test_{m}"].mean()), 3),
                "desvio": round(float(scores[f"test_{m}"].std()), 3)}
            for m in ("precision", "recall", "f1")},
        "teste": {"precisao": round(float(precision_score(y_te, pred)), 3),
                  "recall": round(float(recall_score(y_te, pred)), 3),
                  "f1": round(float(f1_score(y_te, pred)), 3),
                  "matriz_confusao": confusion_matrix(y_te, pred).tolist()},
        "aviso": "dados de treino sinteticos (ver ml/dados_treino.py)",
    }
    relatorio["_texto"] = classification_report(y_te, pred, target_names=["normal", "ataque"])
    return modelo, relatorio


def treinar_e_salvar(pasta=PASTA):
    modelo_path, hash_path, metricas_path = caminhos(pasta)
    modelo_path.parent.mkdir(parents=True, exist_ok=True)
    modelo, relatorio = treinar()
    texto = relatorio.pop("_texto")
    joblib.dump(modelo, modelo_path)
    hash_path.write_text(calcular_hash_arquivo(str(modelo_path)) + "\n", encoding="utf-8")
    metricas_path.write_text(json.dumps(relatorio, indent=2, ensure_ascii=False), encoding="utf-8")
    return relatorio, texto


if __name__ == "__main__":
    rel, texto = treinar_e_salvar()
    cv = rel["validacao_cruzada_5_folds"]
    print("=== Validação cruzada (5 folds, treino) ===")
    for m, v in cv.items():
        print(f"{m:<10}: {v['media']:.3f} (+/- {v['desvio']:.3f})")
    print("\n=== Conjunto de teste ===")
    print(texto)
    print("Matriz de confusão:", rel["teste"]["matriz_confusao"])
    print(f"Modelo salvo em {MODELO}\nHash SHA-256: {caminhos()[1].read_text().strip()}")
    sys.exit(0)
