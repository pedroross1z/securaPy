"""Exercicio 10.3 - Enriquecedor de IPs com cache e backoff em 429.

Evolui o enriquecimento.py do SecuraPy (1o semestre):
  + cache de resultados bem-sucedidos (falhas de rede NAO entram no cache,
    senao um timeout "envenenaria" o IP para sempre);
  + retry com backoff exponencial em HTTP 429;
  + contadores para o resumo (consultas HTTP / cache hits / internos);
  + marca IPs presentes na blacklist como suspeitos.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import comum  # noqa: E402,F401

import requests  # noqa: E402
from enriquecimento import _parsear_octetos, eh_ip_privado  # noqa: E402  (SecuraPy)

URL = "https://ipinfo.io/{ip}/json"
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172"}


class Enriquecedor:
    def __init__(self, get=requests.get, dormir=time.sleep, tentativas=3, blacklist=BLACKLIST):
        self._get, self._dormir, self._tentativas = get, dormir, tentativas
        self.blacklist = set(blacklist)
        self.cache = {}
        self.consultas_http = self.cache_hits = self.internos = 0

    def _consultar_http(self, ip):
        """Retorna dict da API, ou None se falhar. Faz backoff em 429."""
        for i in range(self._tentativas):
            self.consultas_http += 1
            try:
                r = self._get(URL.format(ip=ip), timeout=5)
            except requests.exceptions.RequestException:
                return None
            if r.status_code == 429:
                if i < self._tentativas - 1:
                    self._dormir(2 ** i)             # 1s, 2s, 4s...
                continue
            if r.status_code != 200:
                return None
            try:
                return r.json()
            except ValueError:
                return None
        return None

    def enriquecer(self, ip):
        """Retorna dict com origem = INTERNO | CACHE | API | FALHA."""
        if _parsear_octetos(ip) is None:
            return {"ip": ip, "origem": "FALHA", "descricao": "IP inválido", "externo": False}
        if eh_ip_privado(ip):
            self.internos += 1
            return {"ip": ip, "origem": "INTERNO", "descricao": "Rede Interna (não consultado)",
                    "externo": False, "suspeito": False}
        if ip in self.cache:
            self.cache_hits += 1
            return {**self.cache[ip], "origem": "CACHE"}

        dados = self._consultar_http(ip)
        if dados is None:
            return {"ip": ip, "origem": "FALHA", "externo": True, "suspeito": ip in self.blacklist,
                    "descricao": "consulta indisponível (não cacheado)"}
        resultado = {
            "ip": ip, "externo": True, "suspeito": ip in self.blacklist,
            "descricao": f"{dados.get('city', '?')} / {dados.get('country', '?')} / {dados.get('org', '?')}",
        }
        self.cache[ip] = resultado
        return {**resultado, "origem": "API"}

    def relatorio(self, ips):
        linhas = []
        for ip in ips:
            r = self.enriquecer(ip)
            if r["origem"] == "INTERNO":
                linhas.append(f"{ip:<15} -> {r['descricao']}")
            elif r["origem"] == "CACHE":
                linhas.append(f"{ip:<15} -> [CACHE] sem nova chamada HTTP")
            else:
                marca = "EXTERNO, suspeito" if r.get("suspeito") else "EXTERNO"
                linhas.append(f"{ip:<15} -> {r['descricao']} ({marca})")
        linhas.append(f"=== Resumo === Consultas HTTP: {self.consultas_http} | "
                      f"Cache hits: {self.cache_hits} | Internos: {self.internos}")
        return "\n".join(linhas)


if __name__ == "__main__":
    ips = ["8.8.8.8", "1.1.1.1", "185.220.101.1", "192.168.1.10", "8.8.8.8"]
    print(Enriquecedor().relatorio(ips))
