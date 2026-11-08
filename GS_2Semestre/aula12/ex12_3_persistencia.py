"""Exercicio 12.3 - Persistencia do modelo com verificacao de integridade (SHA-256).

Reaproveita calcular_hash_arquivo() do integridade.py do SecuraPy (1o semestre).

Por que verificar? joblib/pickle EXECUTA codigo ao carregar. Um .pkl adulterado
equivale a execucao remota de codigo (OWASP A08). Por isso a regra aqui e:
verificar o hash ANTES de chamar joblib.load().
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import comum  # noqa: E402

import joblib  # noqa: E402
from integridade import calcular_hash_arquivo  # noqa: E402  (SecuraPy)

from ex12_2_torneio import otimizar, torneio  # noqa: E402

MODELO = comum.SAIDA_DIR / "modelo_seguranca.pkl"
HASH = comum.SAIDA_DIR / "modelo_seguranca.sha256"


def salvar_modelo(modelo, caminho=MODELO, arq_hash=HASH):
    caminho.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(modelo, caminho)
    h = calcular_hash_arquivo(str(caminho))
    arq_hash.write_text(h + "\n", encoding="utf-8")
    return h


class ModeloAdulterado(Exception):
    pass


def carregar_verificado(caminho=MODELO, arq_hash=HASH):
    esperado = arq_hash.read_text(encoding="utf-8").strip()
    if calcular_hash_arquivo(str(caminho)) != esperado:
        raise ModeloAdulterado("ALERTA: arquivo do modelo foi modificado!")
    return joblib.load(caminho)


if __name__ == "__main__":
    vencedor = max((m := torneio()), key=m.get)
    melhor = otimizar(vencedor).best_estimator_
    h = salvar_modelo(melhor)
    print(f"Modelo salvo: {MODELO.name}")
    print(f"Hash SHA-256: {h} ({len(h)} caracteres)")

    print("Recarregando e verificando integridade...")
    modelo = carregar_verificado()
    print("Hash confere: modelo íntegro. Previsão de teste:", modelo.predict([[58000, 4444, 19.0]]).tolist())

    print("\n-- Simulando adulteração do arquivo --")
    with open(MODELO, "ab") as f:
        f.write(b"\x00")
    try:
        carregar_verificado()
    except ModeloAdulterado as e:
        print(e)
    finally:
        salvar_modelo(melhor)                     # restaura um modelo valido
