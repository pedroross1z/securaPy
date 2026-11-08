"""Extracao de features por IP a partir dos eventos normalizados (Modulo C).

A mesma funcao alimenta o treino e a classificacao - assim nao existe divergencia
entre as features vistas no treino e as vistas em producao.
"""
from core.detector import _extrair_kv

FEATURES = ["n_fail", "portas_distintas", "em_blacklist", "web_erros", "total_eventos"]


def extrair_features(eventos, blacklist=frozenset()):
    """Retorna {ip: {feature: valor}} para todos os IPs vistos nos eventos."""
    por_ip = {}
    for e in eventos:
        ip = e.get("ip")
        if not ip:
            continue
        acc = por_ip.setdefault(ip, {"n_fail": 0, "portas": set(), "web_erros": 0, "total_eventos": 0})
        acc["total_eventos"] += 1
        kv = _extrair_kv(e.get("detalhes", ""))
        if e.get("fonte") == "auth" and e.get("tipo") == "FAIL":
            acc["n_fail"] += 1
        elif e.get("fonte") == "firewall" and e.get("tipo") == "BLOCK":
            try:
                acc["portas"].add(int(kv.get("dport", "")))
            except ValueError:
                pass
        elif e.get("fonte") == "web":
            try:
                if int(kv.get("status", 0)) >= 400:
                    acc["web_erros"] += 1
            except ValueError:
                pass
    return {ip: {"n_fail": a["n_fail"], "portas_distintas": len(a["portas"]),
                 "em_blacklist": int(ip in blacklist), "web_erros": a["web_erros"],
                 "total_eventos": a["total_eventos"]}
            for ip, a in por_ip.items()}


def para_matriz(features_por_ip):
    """({ip: feats}) -> (lista_de_ips, lista_de_linhas) na ordem fixa de FEATURES."""
    ips = sorted(features_por_ip)
    return ips, [[features_por_ip[ip][f] for f in FEATURES] for ip in ips]
