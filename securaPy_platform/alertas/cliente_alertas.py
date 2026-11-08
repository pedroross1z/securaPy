"""
Modulo 4b - Cliente de Alertas
Conecta ao servidor de alertas e recebe notificacoes em tempo real.
Permite enviar comandos: /status, /historico, /sair
"""

import socket
import threading

HOST = "127.0.0.1"
PORTA = 9999


def receber_alertas(cliente):
    """Thread que fica ouvindo mensagens do servidor e exibindo no terminal."""
    while True:
        try:
            dados = cliente.recv(4096)
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            print("\n[INFO] Conexao com o servidor foi perdida.")
            break

        if not dados:
            print("\n[INFO] Servidor encerrou a conexao.")
            break

        mensagem = dados.decode("utf-8", errors="ignore")
        print(mensagem, end="" if mensagem.endswith("\n") else "\n")


def conectar_servidor(host=HOST, porta=PORTA):
    """Conecta ao servidor de alertas e inicia a interacao."""
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        cliente.connect((host, porta))
    except ConnectionRefusedError:
        print(f"[ERRO] Servidor recusou a conexao em {host}:{porta}. Esta no ar?")
        cliente.close()
        return
    except OSError as e:
        print(f"[ERRO] Falha ao conectar em {host}:{porta}: {e}")
        cliente.close()
        return

    print(f"[INFO] Conectado ao servidor {host}:{porta}")
    print("Digite /status, /historico ou /sair para interagir.\n")

    thread = threading.Thread(target=receber_alertas, args=(cliente,), daemon=True)
    thread.start()

    try:
        while True:
            try:
                comando = input().strip()
            except EOFError:
                break

            if not comando:
                continue

            try:
                cliente.sendall((comando + "\n").encode("utf-8"))
            except OSError:
                print("[ERRO] Nao foi possivel enviar — conexao perdida.")
                break

            if comando == "/sair":
                break
    except KeyboardInterrupt:
        print("\n[INFO] Encerrando cliente (Ctrl+C)...")
    finally:
        try:
            cliente.close()
        except OSError:
            pass


if __name__ == "__main__":
    conectar_servidor()
