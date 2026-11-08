"""Exercicio 4.1 - Classificador de phishing (Random Forest)."""
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, f1_score, precision_score,
                             recall_score, classification_report)
from sklearn.model_selection import train_test_split

# [qtd_links, tem_anexo, urgencia_no_assunto, dominio_suspeito, erros_gramaticais]
X = np.array([
    [1, 0, 0, 0, 0], [0, 0, 0, 0, 1], [2, 1, 0, 0, 0], [1, 0, 0, 0, 0],
    [8, 1, 1, 1, 5], [12, 0, 1, 1, 8], [6, 1, 1, 1, 3], [10, 1, 1, 1, 6],
    [0, 0, 0, 0, 0], [15, 1, 1, 1, 9],
])
y = np.array([0, 0, 0, 0, 1, 1, 1, 1, 0, 1])   # 0 = legitimo, 1 = phishing


def treinar():
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.3, random_state=42)
    modelo = RandomForestClassifier(n_estimators=100, random_state=42).fit(X_tr, y_tr)
    return modelo, X_te, y_te


if __name__ == "__main__":
    modelo, X_te, y_te = treinar()
    prev = modelo.predict(X_te)
    print(f"Acurácia : {accuracy_score(y_te, prev):.2f}")
    print(f"Precisão : {precision_score(y_te, prev, zero_division=0):.2f}")
    print(f"Recall   : {recall_score(y_te, prev, zero_division=0):.2f}")
    print(f"F1       : {f1_score(y_te, prev, zero_division=0):.2f}")
    print(classification_report(y_te, prev, zero_division=0))

    novo = [[11, 1, 1, 1, 7]]
    print("Caso novo [11,1,1,1,7] ->", "Phishing" if modelo.predict(novo)[0] == 1 else "Legítimo")
