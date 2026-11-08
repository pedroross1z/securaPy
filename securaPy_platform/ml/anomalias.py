"""Bonus: deteccao de anomalias nao supervisionada (Isolation Forest) por IP.

Complementa o classificador supervisionado: acha comportamento estranho SEM rotulo,
util para padroes que as regras e o treino nao conhecem.
"""
import numpy as np
from sklearn.ensemble import IsolationForest

from ml.features import para_matriz

MIN_IPS = 6          # com poucos pontos o Isolation Forest e instavel: nao arrisca


def detectar_anomalias(features_por_ip, contamination=0.15):
    """Retorna lista [{ip, anomalia_score}] dos IPs anomalos (mais anomalo primeiro)."""
    if len(features_por_ip) < MIN_IPS:
        return []
    ips, matriz = para_matriz(features_por_ip)
    modelo = IsolationForest(contamination=contamination, random_state=42).fit(np.array(matriz))
    marcas = modelo.predict(matriz)
    scores = -modelo.score_samples(matriz)
    achados = [{"ip": ip, "anomalia_score": round(float(s), 3)}
               for ip, m, s in zip(ips, marcas, scores) if m == -1]
    return sorted(achados, key=lambda a: -a["anomalia_score"])
