"""CP1 - Exercicios 7, 8 e 9: classificador de trafego, anomalias e metricas honestas."""
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import train_test_split

# ---------------------------------------------------------------- Exercicio 7
# Features: [bytes, porta, duracao]
X = np.array([
    [500, 80, 0.1], [1200, 80, 0.5], [64, 22, 0.02], [64000, 4444, 10.0], [45000, 8080, 15.0],
    [60000, 31337, 20.0], [800, 443, 0.3], [300, 53, 0.05], [55000, 9999, 18.0], [200, 25, 0.2],
])
y = np.array([0, 0, 0, 1, 1, 1, 0, 0, 1, 0])
CASO_NOVO = [[58000, 4444, 16.0]]


def ex07_classificador():
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.3, random_state=42)
    modelo = RandomForestClassifier(n_estimators=100, random_state=42).fit(X_tr, y_tr)
    acuracia = accuracy_score(y_te, modelo.predict(X_te))
    return modelo, acuracia


# ---------------------------------------------------------------- Exercicio 8
# [requisicoes_min, conexoes_simultaneas]
TRAFEGO = np.array([[100, 5], [120, 6], [110, 5], [105, 4], [50000, 500], [109, 5], [111, 6], [45000, 450]])


def ex08_anomalias():
    return IsolationForest(contamination=0.25, random_state=42).fit_predict(TRAFEGO)


# ---------------------------------------------------------------- Exercicio 9
Y_TRUE = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1]   # 8 normais, 2 ataques
Y_PRED = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1]   # perdeu 1 ataque


def ex09_metricas(y_true=Y_TRUE, y_pred=Y_PRED):
    return {"matriz": confusion_matrix(y_true, y_pred).tolist(),
            "acuracia": accuracy_score(y_true, y_pred),
            "precisao": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0),
            "f1": f1_score(y_true, y_pred, zero_division=0)}


if __name__ == "__main__":
    print("=== Exercício 7 ===")
    modelo, acc = ex07_classificador()
    print(f"Acurácia no teste: {acc:.2f}")
    print("Caso novo [58000,4444,16.0] ->", "Malicioso (1)" if modelo.predict(CASO_NOVO)[0] else "Normal (0)")

    print("\n=== Exercício 8 ===")
    for i, (a, r) in enumerate(zip(TRAFEGO, ex08_anomalias())):
        print(f"Amostra {i}: {a.tolist()} -> {'ANOMALIA' if r == -1 else 'Normal'}")

    print("\n=== Exercício 9 ===")
    m = ex09_metricas()
    print(f"Matriz: {m['matriz']}")
    print(f"Acurácia: {m['acuracia']:.2f} | Precisão: {m['precisao']:.2f} | "
          f"Recall: {m['recall']:.2f} | F1: {m['f1']:.2f}")
    # Comentário: a acurácia 0.90 mascara que METADE dos ataques passou (recall 0.50); com
    # classes desbalanceadas, "chutar sempre normal" já daria 0.80 de acurácia sem detectar nada.
