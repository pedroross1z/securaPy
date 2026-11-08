"""Dataset de treino SINTETICO (reprodutivel, seed fixa).

Nao existe base real rotulada neste projeto: os 3 logs de teste tem so ~10 IPs. Por isso o
gerador cria perfis de comportamento por IP, com sobreposicao e ruido de rotulo (para as
metricas nao serem triviais), e o modelo e depois conferido nos IPs REAIS dos logs
(cenarios C2/C3). Perfis de ataque: brute force, port scan, ataque web e ataque "lento".
"""
import numpy as np

from ml.features import FEATURES


def gerar_dataset(n=900, seed=42, ruido_rotulo=0.03):
    rnd = np.random.RandomState(seed)
    X = np.zeros((n, len(FEATURES)))
    y = np.zeros(n, dtype=int)
    for i in range(n):
        if rnd.rand() < 0.35:
            y[i] = 1
            perfil = rnd.choice(["brute", "scan", "web", "lento"], p=[0.35, 0.3, 0.25, 0.10])
            if perfil == "brute":
                fails, portas, web = rnd.randint(5, 41), rnd.randint(0, 3), rnd.randint(0, 7)
            elif perfil == "scan":
                fails, portas, web = rnd.randint(0, 4), rnd.randint(3, 21), rnd.randint(0, 5)
            elif perfil == "web":
                fails, portas, web = rnd.randint(0, 3), rnd.randint(0, 3), rnd.randint(4, 26)
            else:                                                    # ataque lento: quase normal
                fails, portas, web = rnd.randint(2, 6), rnd.randint(1, 4), rnd.randint(1, 5)
            em_bl = int(rnd.rand() < 0.55)
            total = fails + portas + web + rnd.randint(0, 6)
        else:
            fails = rnd.choice([0, 0, 0, 1, 1, 2, 3])
            portas, web = rnd.randint(0, 3), rnd.choice([0, 0, 0, 1, 1, 2, 3])
            em_bl = int(rnd.rand() < 0.01)
            total = fails + portas + web + rnd.randint(1, 15)
        X[i] = [fails, portas, em_bl, web, max(total, 1)]
    flips = rnd.rand(n) < ruido_rotulo                              # ruido de rotulo
    y[flips] = 1 - y[flips]
    return X, y
