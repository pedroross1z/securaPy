"""
Modulo 3 - Detector de Anomalias
Analisa o conjunto de eventos para identificar padroes de ataque
que so ficam visiveis quando multiplos eventos sao correlacionados.

Detecta:
- Brute Force: muitas tentativas de login falhas do mesmo IP
- Port Scan: mesmo IP tentando acessar muitas portas distintas
- IPs em Blacklist: IPs conhecidamente maliciosos presentes nos logs
"""

from datetime import datetime

from core.regras import classificar_severidade


def _extrair_kv(detalhes):
    pares = {}
    if not isinstance(detalhes, str):
        return pares
    for token in detalhes.split():
        if "=" in token:
            chave, _, valor = token.partition("=")
            if chave:
                pares[chave] = valor
    return pares


def _severidade_brute(tentativas, threshold):
    if tentativas > 20:
        return "CRITICA"
    if tentativas > 10:
        return "ALTA"
    if tentativas > 5:
        return "MEDIA"
    return "BAIXA"


def _severidade_scan(quantidade, threshold):
    if quantidade > 10:
        return "CRITICA"
    if quantidade > 5:
        return "ALTA"
    return "MEDIA"


def detectar_brute_force(eventos, threshold=5):
    """Identifica IPs com muitas tentativas de login falhas."""
    contagem = {}
    usuarios = {}

    for evento in eventos:
        if evento.get("fonte") != "auth" or evento.get("tipo") != "FAIL":
            continue
        ip = evento.get("ip")
        if not ip:
            continue
        contagem[ip] = contagem.get(ip, 0) + 1
        usuario = _extrair_kv(evento.get("detalhes", "")).get("usuario")
        if usuario:
            usuarios.setdefault(ip, set()).add(usuario)

    resultado = {}
    for ip, tentativas in contagem.items():
        if tentativas < threshold:
            continue
        resultado[ip] = {
            "tentativas": tentativas,
            "usuarios": sorted(usuarios.get(ip, set())),
            "severidade": _severidade_brute(tentativas, threshold),
        }
    return resultado


def detectar_brute_force_temporal(eventos, threshold=5, janela_segundos=60):
    """Detecta brute force por janela de tempo (sliding window).

    Para cada IP, considera-se ataque se houver >= threshold tentativas FAIL
    em qualquer janela contigua de `janela_segundos`.

    Retorna: {ip: {"tentativas_pico": N, "janela_inicio": ts, "janela_fim": ts,
                   "duracao_segundos": N, "usuarios": [...], "severidade": "..."}}
    """
    fails_por_ip = {}
    for evento in eventos:
        if evento.get("fonte") != "auth" or evento.get("tipo") != "FAIL":
            continue
        ip = evento.get("ip")
        if not ip:
            continue
        try:
            ts = datetime.strptime(evento["timestamp"], "%Y-%m-%d %H:%M:%S")
        except (KeyError, ValueError):
            continue
        usuario = _extrair_kv(evento.get("detalhes", "")).get("usuario", "?")
        fails_por_ip.setdefault(ip, []).append((ts, usuario))

    resultado = {}
    for ip, eventos_ip in fails_por_ip.items():
        eventos_ip.sort(key=lambda x: x[0])
        n = len(eventos_ip)
        melhor = 0
        melhor_inicio = melhor_fim = None
        melhor_usuarios = set()

        inicio = 0
        for fim in range(n):
            while (eventos_ip[fim][0] - eventos_ip[inicio][0]).total_seconds() > janela_segundos:
                inicio += 1
            tamanho_janela = fim - inicio + 1
            if tamanho_janela > melhor:
                melhor = tamanho_janela
                melhor_inicio = eventos_ip[inicio][0]
                melhor_fim = eventos_ip[fim][0]
                melhor_usuarios = {eventos_ip[i][1] for i in range(inicio, fim + 1)}

        if melhor >= threshold:
            resultado[ip] = {
                "tentativas_pico": melhor,
                "janela_inicio": melhor_inicio.strftime("%Y-%m-%d %H:%M:%S"),
                "janela_fim": melhor_fim.strftime("%Y-%m-%d %H:%M:%S"),
                "duracao_segundos": int((melhor_fim - melhor_inicio).total_seconds()),
                "usuarios": sorted(melhor_usuarios),
                "severidade": _severidade_brute(melhor, threshold),
            }
    return resultado


def detectar_port_scan(eventos, threshold=3):
    """Identifica IPs que tentaram acessar muitas portas distintas."""
    portas_por_ip = {}

    for evento in eventos:
        if evento.get("fonte") != "firewall" or evento.get("tipo") != "BLOCK":
            continue
        ip = evento.get("ip")
        if not ip:
            continue
        try:
            dport = int(_extrair_kv(evento.get("detalhes", "")).get("dport", ""))
        except (TypeError, ValueError):
            continue
        portas_por_ip.setdefault(ip, set()).add(dport)

    resultado = {}
    for ip, portas in portas_por_ip.items():
        if len(portas) < threshold:
            continue
        resultado[ip] = {
            "portas": portas,
            "quantidade": len(portas),
            "severidade": _severidade_scan(len(portas), threshold),
        }
    return resultado


def verificar_blacklist(eventos, blacklist):
    """Cruza IPs dos eventos com a blacklist."""
    ips_eventos = {evento["ip"] for evento in eventos if evento.get("ip")}
    ips_encontrados = ips_eventos & blacklist

    contagem = {}
    for evento in eventos:
        ip = evento.get("ip")
        if ip in ips_encontrados:
            contagem[ip] = contagem.get(ip, 0) + 1

    return ips_encontrados, contagem


def gerar_resumo_ameacas(brute_force, port_scan, blacklist_resultado):
    """Consolida todas as deteccoes em um resumo unificado ordenado por pontuacao."""
    ips_blacklist, contagem_blacklist = blacklist_resultado

    todos_ips = set(brute_force.keys()) | set(port_scan.keys()) | set(ips_blacklist)

    ameacas = []
    for ip in todos_ips:
        deteccoes = []
        detalhes = {}
        pontuacao = 0

        if ip in brute_force:
            deteccoes.append("brute_force")
            detalhes["brute_force"] = brute_force[ip]
            pontuacao += 5

        if ip in port_scan:
            deteccoes.append("port_scan")
            detalhes["port_scan"] = port_scan[ip]
            pontuacao += 5

        if ip in ips_blacklist:
            deteccoes.append("blacklist")
            detalhes["blacklist"] = {"eventos": contagem_blacklist.get(ip, 0)}
            pontuacao += 5

        ameacas.append({
            "ip": ip,
            "deteccoes": deteccoes,
            "pontuacao": pontuacao,
            "severidade": classificar_severidade(pontuacao),
            "detalhes": detalhes,
        })

    def _intensidade(a):
        d = a["detalhes"]
        return (
            d.get("brute_force", {}).get("tentativas", 0)
            + d.get("port_scan", {}).get("quantidade", 0)
            + d.get("blacklist", {}).get("eventos", 0)
        )

    ameacas.sort(key=lambda a: (a["pontuacao"], _intensidade(a)), reverse=True)
    return ameacas
