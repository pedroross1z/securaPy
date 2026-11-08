"""
Modulo 5 - Enriquecimento de IPs
Adiciona contexto geografico e organizacional aos IPs suspeitos
consultando a API publica do ipinfo.io.

Classifica IPs em privados (rede interna) e publicos, e consulta
apenas os publicos para economizar requisicoes.

Formato do resultado de enriquecimento:
{
    "ip": "185.220.101.1",
    "privado": False,
    "cidade": "Frankfurt am Main",
    "regiao": "Hesse",
    "pais": "DE",
    "org": "AS208294 Fastethernet",
    "hostname": "tor-exit.r2"
}
"""

import json
import requests


_API_URL = "https://ipinfo.io/{ip}/json"
_TIMEOUT = 5


def _parsear_octetos(ip):
    if not isinstance(ip, str):
        return None
    partes = ip.split(".")
    if len(partes) != 4:
        return None
    try:
        octetos = [int(p) for p in partes]
    except ValueError:
        return None
    if any(o < 0 or o > 255 for o in octetos):
        return None
    return octetos


def eh_ip_privado(ip):
    """Verifica se um endereco IP pertence a uma faixa de rede privada (RFC 1918)."""
    octetos = _parsear_octetos(ip)
    if octetos is None:
        return False

    a, b, _, _ = octetos
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    return False


def _resposta_desconhecida(ip, motivo="Desconhecido"):
    return {
        "ip": ip,
        "privado": False,
        "cidade": motivo,
        "regiao": motivo,
        "pais": motivo,
        "org": motivo,
        "hostname": motivo,
    }


def consultar_ip(ip, cache):
    """Consulta a API do ipinfo.io (ou retorna do cache) e devolve dados normalizados."""
    if ip in cache:
        return cache[ip]

    if eh_ip_privado(ip):
        resultado = {
            "ip": ip,
            "privado": True,
            "cidade": "Rede Interna",
            "regiao": "Rede Interna",
            "pais": "Rede Interna",
            "org": "Rede Interna",
            "hostname": "Rede Interna",
        }
        cache[ip] = resultado
        return resultado

    if _parsear_octetos(ip) is None:
        resultado = _resposta_desconhecida(ip, motivo="IP invalido")
        cache[ip] = resultado
        return resultado

    try:
        resposta = requests.get(_API_URL.format(ip=ip), timeout=_TIMEOUT)
    except requests.exceptions.Timeout:
        print(f"[WARN] Timeout ao consultar {ip}")
        return _resposta_desconhecida(ip)
    except requests.exceptions.ConnectionError:
        print(f"[WARN] Erro de conexao ao consultar {ip}")
        return _resposta_desconhecida(ip)
    except requests.exceptions.RequestException as e:
        print(f"[WARN] Erro de requisicao para {ip}: {e}")
        return _resposta_desconhecida(ip)

    if resposta.status_code == 429:
        print(f"[WARN] Rate limit (429) ao consultar {ip}")
        return _resposta_desconhecida(ip)

    if resposta.status_code != 200:
        print(f"[WARN] Status {resposta.status_code} ao consultar {ip}")
        return _resposta_desconhecida(ip)

    try:
        dados = resposta.json()
    except (json.JSONDecodeError, ValueError):
        print(f"[WARN] Resposta nao-JSON ao consultar {ip}")
        return _resposta_desconhecida(ip)

    resultado = {
        "ip": dados.get("ip", ip),
        "privado": False,
        "cidade": dados.get("city", "Desconhecido"),
        "regiao": dados.get("region", "Desconhecido"),
        "pais": dados.get("country", "Desconhecido"),
        "org": dados.get("org", "Desconhecido"),
        "hostname": dados.get("hostname", "Desconhecido"),
    }
    cache[ip] = resultado
    return resultado


def enriquecer_alertas(alertas, cache):
    """Adiciona o campo 'geolocalizacao' a cada alerta, reaproveitando o cache."""
    if not alertas:
        return []

    ips_unicos = {a["ip"] for a in alertas if a.get("ip")}
    geo_por_ip = {ip: consultar_ip(ip, cache) for ip in ips_unicos}

    for alerta in alertas:
        alerta["geolocalizacao"] = geo_por_ip.get(alerta.get("ip"))

    return alertas


def exibir_enriquecimento(dados_ip):
    """Exibe as informacoes de um IP de forma formatada no terminal."""
    if not dados_ip:
        print("[INFO] Sem dados de enriquecimento.")
        return

    tipo = "PRIVADO (Rede Interna)" if dados_ip.get("privado") else "PUBLICO"
    print(f"{'IP:':<12} {dados_ip.get('ip', '-')}")
    print(f"{'Tipo:':<12} {tipo}")
    print(f"{'Cidade:':<12} {dados_ip.get('cidade', '-')}")
    print(f"{'Regiao:':<12} {dados_ip.get('regiao', '-')}")
    print(f"{'Pais:':<12} {dados_ip.get('pais', '-')}")
    print(f"{'Org:':<12} {dados_ip.get('org', '-')}")
    print(f"{'Hostname:':<12} {dados_ip.get('hostname', '-')}")
