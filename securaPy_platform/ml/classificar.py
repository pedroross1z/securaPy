"""Classificacao de risco por IP (Modulo C).

O modelo e carregado SOMENTE depois de conferir o SHA-256: joblib/pickle executa codigo ao
carregar, entao um .pkl adulterado equivale a execucao remota (OWASP A08).
"""
import threading
from pathlib import Path

import joblib

from core.integridade import calcular_hash_arquivo
from ml import treinar
from ml.features import FEATURES, para_matriz

LIMIAR_ATAQUE = 0.5
LIMIAR_ALTO, LIMIAR_MEDIO = 0.7, 0.4


class ModeloAdulterado(Exception):
    pass


class ModeloAusente(Exception):
    pass


def carregar_modelo(pasta=treinar.PASTA):
    modelo_path, hash_path, _ = treinar.caminhos(pasta)
    if not modelo_path.is_file() or not hash_path.is_file():
        raise ModeloAusente(f"modelo ou hash não encontrado em {pasta}")
    esperado = hash_path.read_text(encoding="utf-8").strip()
    if calcular_hash_arquivo(str(modelo_path)) != esperado:
        raise ModeloAdulterado("ALERTA: arquivo do modelo foi modificado (hash não confere)!")
    return joblib.load(modelo_path)


def nivel_de_risco(score):
    if score >= LIMIAR_ALTO:
        return "ALTO"
    if score >= LIMIAR_MEDIO:
        return "MEDIO"
    return "BAIXO"


def pontuar(features_por_ip, modelo):
    """Retorna lista [{ip, score, nivel, rotulo, features}] ordenada do maior para o menor risco."""
    if not features_por_ip:
        return []
    ips, matriz = para_matriz(features_por_ip)
    probas = modelo.predict_proba(matriz)[:, list(modelo.classes_).index(1)]
    resultado = [{"ip": ip, "score": round(float(p), 3), "nivel": nivel_de_risco(p),
                  "rotulo": "ataque" if p >= LIMIAR_ATAQUE else "normal",
                  "features": features_por_ip[ip]} for ip, p in zip(ips, probas)]
    return sorted(resultado, key=lambda r: (-r["score"], r["ip"]))


class Classificador:
    """Carrega o modelo uma unica vez (thread-safe). Se faltar, treina; se estiver adulterado, RECUSA."""

    def __init__(self, pasta=treinar.PASTA, treinar_se_ausente=True):
        self.pasta, self.treinar_se_ausente = Path(pasta), treinar_se_ausente
        self._modelo, self._lock = None, threading.Lock()

    @property
    def modelo(self):
        with self._lock:
            if self._modelo is None:
                try:
                    self._modelo = carregar_modelo(self.pasta)
                except ModeloAusente:
                    if not self.treinar_se_ausente:
                        raise
                    treinar.treinar_e_salvar(self.pasta)
                    self._modelo = carregar_modelo(self.pasta)
            return self._modelo

    def pontuar(self, features_por_ip):
        return pontuar(features_por_ip, self.modelo)

    def pontuar_ip(self, ip, features_por_ip):
        """Score de um IP especifico (None se o IP nao aparece nas features)."""
        if ip not in features_por_ip:
            return None
        return pontuar({ip: features_por_ip[ip]}, self.modelo)[0]
