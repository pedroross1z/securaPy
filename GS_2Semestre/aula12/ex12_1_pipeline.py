"""Exercicio 12.1 - Pipeline (StandardScaler + RandomForest) com validacao cruzada de 5 folds."""
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from dados import X, y


def criar_pipeline():
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(n_estimators=100, random_state=42)),
    ])


def avaliar(pipeline=None, folds=5):
    # StratifiedKFold mantem a proporcao normal/malicioso em cada fold; embaralhar
    # com seed fixa torna o resultado reprodutivel.
    cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=42)
    return cross_val_score(pipeline or criar_pipeline(), X, y, cv=cv)


if __name__ == "__main__":
    scores = avaliar()
    print("Acurácia por fold:", " ".join(f"{s:.2f}" for s in scores))
    print(f"Acurácia: {scores.mean():.2f} (+/- {scores.std():.2f})")
