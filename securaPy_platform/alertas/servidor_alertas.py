"""
Modulo 4a - Servidor de Alertas em Tempo Real
Servidor TCP que aceita conexoes de multiplos clientes (consoles de monitoramento)
e faz broadcast de alertas de seguranca para todos os clientes conectados.

Comandos suportados pelo cliente:
    /status    - mostra quantos clientes conectados e alertas na sessao
    /historico - envia os ultimos 10 alertas
    /sair      - desconecta do servidor
"""

import socket
import threading

# Configuracao
HOST = "0.0.0.0"
PORTA = 9999
MAX_CLIENTES = 10

# Estado global do servidor
clientes = {}       # {conexao: endereco}
lock = threading.Lock()
historico_alertas = []


def formatar_alerta(alerta_dict):
    """Converte um dicionario de alerta em string formatada para exibicao."""
    timestamp = alerta_dict.get("timestamp", "")
    hora = timestamp.split(" ")[-1] if " " in timestamp else timestamp
    severidade = alerta_dict.get("severidade", "INFO")
    regra_nome = alerta_dict.get("regra_nome", "Regra")
    ip = alerta_dict.get("ip", "?")
    descricao = alerta_dict.get("descricao", "")
    return f"[{hora}] [{severidade}] {regra_nome} - {ip} - {descricao}"


def remover_cliente(conexao):
    """Remove um cliente da lista de conectados e fecha o socket."""
    endereco = None
    with lock:
        endereco = clientes.pop(conexao, None)
    try:
        conexao.close()
    except OSError:
        pass
    if endereco:
        print(f"[INFO] Cliente desconectado: {endereco}")


def broadcast_alerta(alerta):
    """Envia um alerta para todos os clientes conectados."""
    if isinstance(alerta, dict):
        mensagem = formatar_alerta(alerta)
    else:
        mensagem = str(alerta)

    historico_alertas.append(mensagem)
    del historico_alertas[:-500]          # limita o historico em memoria

    payload = (mensagem + "\n").encode("utf-8")

    with lock:
        destinatarios = list(clientes.keys())

    desconectados = []
    for conexao in destinatarios:
        try:
            conexao.sendall(payload)
        except (BrokenPipeError, ConnectionResetError, OSError):
            desconectados.append(conexao)

    for conexao in desconectados:
        remover_cliente(conexao)


def tratar_cliente(conexao, endereco):
    """Gerencia a comunicacao com um cliente individual (uma thread por cliente)."""
    with lock:
        clientes[conexao] = endereco
    print(f"[INFO] Cliente conectado: {endereco}")

    try:
        conexao.sendall(
            "Bem-vindo ao SecuraPy SIEM. Comandos: /status, /historico, /sair\n".encode("utf-8")
        )
    except OSError:
        remover_cliente(conexao)
        return

    try:
        while True:
            try:
                dados = conexao.recv(1024)
            except (ConnectionResetError, ConnectionAbortedError, OSError):
                break

            if not dados:
                break

            comando = dados.decode("utf-8", errors="ignore").strip()
            if not comando:
                continue

            if comando == "/sair":
                try:
                    conexao.sendall("Ate logo!\n".encode("utf-8"))
                except OSError:
                    pass
                break

            elif comando == "/status":
                with lock:
                    n_clientes = len(clientes)
                n_alertas = len(historico_alertas)
                resposta = f"[STATUS] Clientes conectados: {n_clientes} | Alertas na sessao: {n_alertas}\n"
                try:
                    conexao.sendall(resposta.encode("utf-8"))
                except OSError:
                    break

            elif comando == "/historico":
                ultimos = historico_alertas[-10:]
                if not ultimos:
                    resposta = "[HISTORICO] Nenhum alerta registrado.\n"
                else:
                    resposta = "[HISTORICO] Ultimos alertas:\n" + "\n".join(ultimos) + "\n"
                try:
                    conexao.sendall(resposta.encode("utf-8"))
                except OSError:
                    break

            else:
                try:
                    conexao.sendall(
                        f"[ERRO] Comando desconhecido: {comando}\n".encode("utf-8")
                    )
                except OSError:
                    break
    finally:
        remover_cliente(conexao)


def iniciar_servidor(host=HOST, porta=PORTA, parar=None, pronto=None):
    """Inicia o servidor TCP de alertas.

    Evolucao da plataforma: `parar` (threading.Event) encerra o laco; `pronto` (Event) e sinalizado
    quando o socket ja esta escutando. Assim o servidor roda dentro da API (thread) e e testavel."""
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        servidor.bind((host, porta))
    except OSError as e:
        print(f"[ERRO] Nao foi possivel fazer bind em {host}:{porta}: {e}")
        servidor.close()
        return

    servidor.listen(MAX_CLIENTES)
    servidor.settimeout(1.0)
    if pronto is not None:
        pronto.set()
    print(f"[INFO] Servidor de alertas escutando em {host}:{porta}")
    print("[INFO] Pressione Ctrl+C para encerrar.")

    try:
        while not (parar is not None and parar.is_set()):
            try:
                conexao, endereco = servidor.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            thread = threading.Thread(
                target=tratar_cliente,
                args=(conexao, endereco),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        print("\n[INFO] Encerrando servidor (Ctrl+C)...")
    finally:
        with lock:
            for conexao in list(clientes.keys()):
                try:
                    conexao.close()
                except OSError:
                    pass
            clientes.clear()
        servidor.close()
        print("[INFO] Servidor encerrado.")


if __name__ == "__main__":
    iniciar_servidor()


def iniciar_em_thread(host=HOST, porta=PORTA):
    """Sobe o servidor numa thread daemon. Retorna (thread, evento_parar, evento_pronto)."""
    parar, pronto = threading.Event(), threading.Event()
    t = threading.Thread(target=iniciar_servidor, args=(host, porta, parar, pronto), daemon=True)
    t.start()
    return t, parar, pronto
