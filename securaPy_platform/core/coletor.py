"""
Modulo 1 - Coletor de Logs
Responsavel por ler arquivos de log de diferentes fontes (auth, firewall, web),
parsear cada linha e normalizar os eventos em um formato padronizado de dicionario.

Formato padronizado de evento:
{
    "timestamp": "2025-02-20 08:15:01",
    "fonte": "auth",              # auth | firewall | web
    "tipo": "FAIL",               # OK | FAIL | BLOCK | ALLOW | GET | POST | DELETE
    "ip": "185.220.101.1",
    "detalhes": "usuario=admin",  # informacoes extras dependendo da fonte
    "linha_original": "..."       # linha crua do log
}
"""

import os


_TIPOS_AUTH = {"OK", "FAIL"}
_TIPOS_FIREWALL = {"BLOCK", "ALLOW"}
_METODOS_HTTP = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


def _extrair_kv(tokens):
    """Extrai pares chave=valor de uma lista de tokens. Retorna dict."""
    pares = {}
    for token in tokens:
        if "=" in token:
            chave, _, valor = token.partition("=")
            if chave:
                pares[chave] = valor
    return pares


def parsear_linha_auth(linha):
    """
    Parseia uma linha do auth.log e retorna um dicionario normalizado.

    Formato da linha:
        "2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1"
    """
    if not isinstance(linha, str) or not linha.strip():
        return None

    try:
        partes = linha.split()
        if len(partes) < 5:
            return None

        timestamp = f"{partes[0]} {partes[1]}"
        tipo = partes[2]
        if tipo not in _TIPOS_AUTH:
            return None

        kv = _extrair_kv(partes[3:])
        if "usuario" not in kv or "ip" not in kv:
            return None

        return {
            "timestamp": timestamp,
            "fonte": "auth",
            "tipo": tipo,
            "ip": kv["ip"],
            "detalhes": f"usuario={kv['usuario']}",
            "linha_original": linha,
        }
    except (ValueError, IndexError, AttributeError):
        return None


def parsear_linha_firewall(linha):
    """
    Parseia uma linha do firewall.log e retorna um dicionario normalizado.

    Formato da linha:
        "2025-02-20 08:10:02 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=22"
    """
    if not isinstance(linha, str) or not linha.strip():
        return None

    try:
        partes = linha.split()
        if len(partes) < 7:
            return None

        timestamp = f"{partes[0]} {partes[1]}"
        tipo = partes[2]
        if tipo not in _TIPOS_FIREWALL:
            return None

        kv = _extrair_kv(partes[3:])
        campos_obrigatorios = ("proto", "src", "dst", "dport")
        if not all(c in kv for c in campos_obrigatorios):
            return None

        return {
            "timestamp": timestamp,
            "fonte": "firewall",
            "tipo": tipo,
            "ip": kv["src"],
            "detalhes": f"proto={kv['proto']} dst={kv['dst']} dport={kv['dport']}",
            "linha_original": linha,
        }
    except (ValueError, IndexError, AttributeError):
        return None


def parsear_linha_web(linha):
    """
    Parseia uma linha do web_access.log e retorna um dicionario normalizado.

    Formato da linha:
        "2025-02-20 08:20:01 GET url=/index.html ip=192.168.1.10 status=200"
    """
    if not isinstance(linha, str) or not linha.strip():
        return None

    try:
        partes = linha.split()
        if len(partes) < 6:
            return None

        timestamp = f"{partes[0]} {partes[1]}"
        tipo = partes[2]
        if tipo not in _METODOS_HTTP:
            return None

        kv = _extrair_kv(partes[3:])
        campos_obrigatorios = ("url", "ip", "status")
        if not all(c in kv for c in campos_obrigatorios):
            return None

        return {
            "timestamp": timestamp,
            "fonte": "web",
            "tipo": tipo,
            "ip": kv["ip"],
            "detalhes": f"url={kv['url']} status={kv['status']}",
            "linha_original": linha,
        }
    except (ValueError, IndexError, AttributeError):
        return None


def carregar_log(caminho_arquivo, fonte):
    """
    Le um arquivo de log e retorna uma lista de eventos normalizados.
    """
    parsers = {
        "auth": parsear_linha_auth,
        "firewall": parsear_linha_firewall,
        "web": parsear_linha_web,
    }

    if fonte not in parsers:
        print(f"[ERRO] Fonte desconhecida: '{fonte}'. Use auth, firewall ou web.")
        return []

    parser = parsers[fonte]
    eventos = []

    try:
        with open(caminho_arquivo, "r", encoding="utf-8") as f:
            linhas = f.readlines()
    except FileNotFoundError:
        print(f"[ERRO] Arquivo nao encontrado: {caminho_arquivo}")
        return []
    except PermissionError:
        print(f"[ERRO] Sem permissao para ler: {caminho_arquivo}")
        return []
    except OSError as e:
        print(f"[ERRO] Erro de I/O ao ler {caminho_arquivo}: {e}")
        return []

    if not linhas:
        print(f"[INFO] Arquivo vazio: {caminho_arquivo}")
        return []

    for numero, linha_bruta in enumerate(linhas, start=1):
        linha = linha_bruta.rstrip("\r\n")
        if not linha.strip():
            continue

        evento = parser(linha)
        if evento is None:
            print(f"[WARN] Linha ignorada: {caminho_arquivo}:{numero}: {linha!r}")
            continue

        eventos.append(evento)

    return eventos


def carregar_todos_os_logs(pasta_logs):
    """
    Le todos os arquivos .log da pasta e retorna uma lista unificada de eventos.
    """
    try:
        arquivos = os.listdir(pasta_logs)
    except FileNotFoundError:
        print(f"[ERRO] Pasta nao encontrada: {pasta_logs}")
        return []
    except PermissionError:
        print(f"[ERRO] Sem permissao para acessar: {pasta_logs}")
        return []
    except NotADirectoryError:
        print(f"[ERRO] Caminho nao e um diretorio: {pasta_logs}")
        return []

    eventos = []

    for arquivo in sorted(arquivos):
        if not arquivo.endswith(".log"):
            continue

        nome_lower = arquivo.lower()
        if "auth" in nome_lower:
            fonte = "auth"
        elif "firewall" in nome_lower:
            fonte = "firewall"
        elif "web" in nome_lower:
            fonte = "web"
        else:
            print(f"[WARN] Fonte desconhecida para arquivo: {arquivo} (ignorado)")
            continue

        caminho = os.path.join(pasta_logs, arquivo)
        eventos_arquivo = carregar_log(caminho, fonte)
        print(f"[INFO] {len(eventos_arquivo)} eventos carregados de {arquivo}")
        eventos.extend(eventos_arquivo)

    return eventos


if __name__ == "__main__":
    pasta_base = os.path.dirname(os.path.abspath(__file__))
    pasta_logs = os.path.join(pasta_base, "logs")

    print("=== Caso 1: parse de uma linha auth (FAIL) ===")
    print(parsear_linha_auth("2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1"))

    print("\n=== Caso 2: carregamento individual do auth.log ===")
    eventos_auth = carregar_log(os.path.join(pasta_logs, "auth.log"), "auth")
    print(f"Total de eventos auth: {len(eventos_auth)}")

    print("\n=== Caso 3: carregamento unificado de todos os logs ===")
    todos = carregar_todos_os_logs(pasta_logs)
    print(f"Total geral: {len(todos)} eventos")
    fontes = {e["fonte"] for e in todos}
    print(f"Fontes detectadas: {fontes}")
