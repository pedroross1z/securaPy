"""Exercicio 12.2 - Torneio de algoritmos (RandomForest x SVM x KNN) + GridSearch no vencedor.

Todos os modelos entram em um Pipeline com StandardScaler: SVM e KNN dependem da
escala das features (bytes ~ 10^4 vs duracao ~ 10^0); sem normalizar, a comparacao
seria injusta com eles.
"""
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, StratifiedKFold, cross_val_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

from dados import X, y

CV = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)


def _pipe(clf):
    return Pipeline([("scaler", StandardScaler()), ("clf", clf)])


MODELOS = {
    "RandomForest": _pipe(RandomForestClassifier(random_state=42)),
    "SVM": _pipe(SVC()),
    "KNN": _pipe(KNeighborsClassifier()),
}

GRADES = {
    "RandomForest": {"clf__n_estimators": [50, 100, 200], "clf__max_depth": [None, 5, 10]},
    "SVM": {"clf__C": [0.1, 1, 10], "clf__kernel": ["linear", "rbf"]},
    "KNN": {"clf__n_neighbors": [1, 3, 5], "clf__weights": ["uniform", "distance"]},
}


def torneio():
    return {nome: cross_val_score(m, X, y, cv=CV).mean() for nome, m in MODELOS.items()}


def otimizar(nome_vencedor):
    busca = GridSearchCV(MODELOS[nome_vencedor], GRADES[nome_vencedor], cv=CV)
    busca.fit(X, y)
    return busca


if __name__ == "__main__":
    placar = torneio()
    for nome, media in placar.items():
        print(f"{nome + ':':<14}{media:.2f}")
    vencedor = max(placar, key=placar.get)       # empate: vale o primeiro da lista
    print(f"Vencedor: {vencedor}")
    busca = otimizar(vencedor)
    print("Melhores parâmetros:", {k.replace("clf__", ""): v for k, v in busca.best_params_.items()})
    print(f"Melhor score (CV): {busca.best_score_:.2f}")
