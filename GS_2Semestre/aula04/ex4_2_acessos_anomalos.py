"""Exercicio 4.2 - Deteccao de acessos anomalos com Isolation Forest."""
import numpy as np
from sklearn.ensemble import IsolationForest

# [hora_do_dia, tentativas_login, bytes_baixados]
acessos = np.array([
    [9, 1, 200], [10, 1, 500], [14, 2, 300], [11, 1, 250], [16, 1, 400],
    [3, 40, 900000],   # madrugada, muitas tentativas, download enorme
    [10, 1, 350], [15, 2, 280],
    [2, 55, 800000],   # outra anomalia
])


def detectar(amostras, contamination=0.25, seed=42):
    """Retorna 1 (normal) ou -1 (anomalia) para cada amostra."""
    return IsolationForest(contamination=contamination, random_state=seed).fit_predict(amostras)


if __name__ == "__main__":
    for i, (amostra, r) in enumerate(zip(acessos, detectar(acessos))):
        print(f"Amostra {i}: {amostra.tolist()} -> {'ANOMALIA' if r == -1 else 'Normal'}")
