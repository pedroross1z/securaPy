"""Exercicio 13.2 - Classificador automatico de logs em lote (LLM + fallback por regras).

1) roda os 3 logs de exemplo do enunciado;
2) roda as linhas SUSPEITAS do auth.log e do web_access.log do SecuraPy (1o semestre).
Se a API falhar (ou nao houver chave), o classificador cai para as regras.
"""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from comum import LOGS_DIR  # noqa: E402
from llm_comum import ROTULOS, classificar_seguro, obter_cliente  # noqa: E402

import coletor  # noqa: E402  (SecuraPy 1o semestre)

EXEMPLOS = [
    "GET /index.html ip=192.168.1.10 status=200",
    "GET /../../etc/passwd ip=91.240.118.172 status=400",
    "POST /login ip=185.220.101.1 status=401 (5x seguidas)",
]


def eh_suspeito(evento):
    """Pre-filtro barato: so manda ao LLM o que merece analise (economiza tokens)."""
    if evento["fonte"] == "auth":
        return evento["tipo"] == "FAIL"
    if evento["fonte"] == "web":
        return "status=200" not in evento["detalhes"] or any(
            p in evento["detalhes"].lower() for p in ("../", "<script", "wp-admin", "union", "'"))
    return False


def classificar_lote(client, logs):
    resultados = [(log, classificar_seguro(client, log)) for log in logs]
    contagem = Counter(r["rotulo"] for _, r in resultados)
    return resultados, contagem


def imprimir(resultados, contagem):
    for log, r in resultados:
        print(f"[{r['rotulo']:<8}] {log}  ({r['motivo']}; via {r['origem']})")
    print("=== Resumo === " + " | ".join(f"{k}:{contagem.get(k, 0)}" for k in ROTULOS))


if __name__ == "__main__":
    client, mock = obter_cliente()
    if mock:
        print("[aviso] OPENAI_API_KEY não definida — usando modelo simulado (mock).\n")

    print("##### Logs de exemplo do enunciado")
    imprimir(*classificar_lote(client, EXEMPLOS))

    print("\n##### Linhas suspeitas do auth.log e web_access.log (SecuraPy)")
    eventos = (coletor.carregar_log(str(LOGS_DIR / "auth.log"), "auth")
               + coletor.carregar_log(str(LOGS_DIR / "web_access.log"), "web"))
    suspeitos = [e["linha_original"] for e in eventos if eh_suspeito(e)]
    print(f"{len(suspeitos)} linhas suspeitas de {len(eventos)} eventos")
    imprimir(*classificar_lote(client, suspeitos))
