"""
Modulo Bonus - Verificacao de Integridade dos Logs
Gera e compara hashes SHA-256 dos arquivos de log para detectar
alteracoes nao autorizadas entre execucoes.
"""

import hashlib
import json
import os


def calcular_hash_arquivo(caminho, bloco=65536):
    """Calcula SHA-256 de um arquivo, lendo em blocos para suportar arquivos grandes."""
    sha = hashlib.sha256()
    try:
        with open(caminho, "rb") as f:
            while True:
                dados = f.read(bloco)
                if not dados:
                    break
                sha.update(dados)
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"[ERRO] Nao foi possivel ler {caminho}: {e}")
        return None
    return sha.hexdigest()


def _arquivos_log(pasta_logs):
    if not os.path.isdir(pasta_logs):
        return []
    return sorted(f for f in os.listdir(pasta_logs) if f.endswith(".log"))


def salvar_hashes(pasta_logs, arquivo_hashes):
    """Calcula o hash de cada .log da pasta e salva em JSON."""
    hashes = {}
    for nome in _arquivos_log(pasta_logs):
        caminho = os.path.join(pasta_logs, nome)
        h = calcular_hash_arquivo(caminho)
        if h:
            hashes[nome] = h

    pasta = os.path.dirname(arquivo_hashes)
    if pasta:
        os.makedirs(pasta, exist_ok=True)

    with open(arquivo_hashes, "w", encoding="utf-8") as f:
        json.dump(hashes, f, indent=2)

    print(f"[OK] {len(hashes)} hash(es) salvos em {arquivo_hashes}")
    return hashes


def verificar_hashes(pasta_logs, arquivo_hashes):
    """Compara hashes atuais com os salvos. Retorna dict {arquivo: status}.

    Status possiveis: 'OK', 'MODIFICADO', 'NOVO', 'REMOVIDO'.
    """
    try:
        with open(arquivo_hashes, "r", encoding="utf-8") as f:
            hashes_salvos = json.load(f)
    except FileNotFoundError:
        print(f"[INFO] Nenhum hash anterior em {arquivo_hashes}. Rode 'salvar' primeiro.")
        return {}
    except json.JSONDecodeError as e:
        print(f"[ERRO] Hashes corrompidos em {arquivo_hashes}: {e}")
        return {}

    arquivos_atuais = set(_arquivos_log(pasta_logs))
    arquivos_salvos = set(hashes_salvos.keys())

    relatorio = {}

    for nome in sorted(arquivos_atuais | arquivos_salvos):
        if nome not in arquivos_salvos:
            relatorio[nome] = "NOVO"
            continue
        if nome not in arquivos_atuais:
            relatorio[nome] = "REMOVIDO"
            continue
        h_atual = calcular_hash_arquivo(os.path.join(pasta_logs, nome))
        if h_atual == hashes_salvos[nome]:
            relatorio[nome] = "OK"
        else:
            relatorio[nome] = "MODIFICADO"

    return relatorio
