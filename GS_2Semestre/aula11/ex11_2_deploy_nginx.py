"""Exercicio 11.2 - Deploy automatizado de Nginx (sobe, valida, derruba e limpa)."""
import socket
import sys
import time

import docker
import requests

NOME = "nginx_deploy_lab"
PORTA = 8080


def porta_em_uso(porta, host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex((host, porta)) == 0


def aguardar_http(url, limite_s=30):
    """Faz polling ate o servico responder (em vez de um sleep fixo)."""
    fim = time.time() + limite_s
    while time.time() < fim:
        try:
            return requests.get(url, timeout=2)
        except requests.exceptions.RequestException:
            time.sleep(1)
    return None


def main(porta=PORTA):
    if porta_em_uso(porta):
        print(f"Erro: porta {porta} em uso")
        return 1
    client = docker.from_env()
    container = None
    try:
        print("Subindo Nginx...")
        container = client.containers.run("nginx:latest", detach=True, name=NOME,
                                          ports={"80/tcp": porta})
        resp = aguardar_http(f"http://localhost:{porta}")
        if resp is None:
            print("Erro: Nginx não respondeu a tempo")
            return 2
        print(f"Nginx respondeu: {resp.status_code} {resp.reason}")
        return 0 if resp.status_code == 200 else 3
    except docker.errors.APIError as e:
        if "port is already allocated" in str(e) or "address already in use" in str(e):
            print(f"Erro: porta {porta} em uso")
        else:
            print(f"Erro do Docker: {e.explanation or e}")
        return 1
    finally:
        if container is not None:
            print("Derrubando e removendo contêiner...")
            container.stop(timeout=5)
            container.remove(force=True)
            print("Concluído. Ambiente limpo.")


if __name__ == "__main__":
    sys.exit(main())
