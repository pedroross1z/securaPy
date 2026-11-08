"""Exercicio 11.3 - Watchdog: vigia um conteiner e o reinicia se parar.

Uso:  python ex11_3_watchdog.py [nome] [intervalo_s] [iteracoes]
"""
import sys
import time
from datetime import datetime

import docker


def _agora():
    return datetime.now().strftime("%H:%M:%S")


def verificar(client, nome):
    """Checa uma vez. Retorna 'ok', 'reiniciado' ou 'falha'."""
    try:
        c = client.containers.get(nome)
    except docker.errors.NotFound:
        print(f"[{_agora()}] {nome}: não existe — ⚠️ ALERTA! Nada para reiniciar.")
        return "falha"
    c.reload()                                  # status atualizado
    if c.status == "running":
        print(f"[{_agora()}] {nome}: running — OK")
        return "ok"
    print(f"[{_agora()}] {nome}: {c.status} — ⚠️ ALERTA! Tentando reiniciar...")
    try:
        c.restart(timeout=5)
        c.reload()
    except docker.errors.APIError as e:
        print(f"[{_agora()}] falha ao reiniciar {nome}: {e.explanation or e}")
        return "falha"
    if c.status == "running":
        print(f"[{_agora()}] {nome} reiniciado com sucesso.")
        return "reiniciado"
    print(f"[{_agora()}] {nome} continua {c.status}.")
    return "falha"


def watchdog(nome="web_lab", intervalo=10, iteracoes=6, client=None, dormir=time.sleep):
    client = client or docker.from_env()
    resultados = []
    for i in range(iteracoes):
        resultados.append(verificar(client, nome))
        if i < iteracoes - 1:
            dormir(intervalo)
    return resultados


if __name__ == "__main__":
    nome = sys.argv[1] if len(sys.argv) > 1 else "web_lab"
    intervalo = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    iteracoes = int(sys.argv[3]) if len(sys.argv) > 3 else 6
    try:
        watchdog(nome, intervalo, iteracoes)
    except KeyboardInterrupt:
        print("\nWatchdog encerrado.")
