"""Orquestracao ponta a ponta (secao 4 do enunciado).

logs -> coletor -> regras -> detector (brute force, port scan, blacklist, janela temporal)
     -> persistencia (Mongo) -> ML (score de risco) -> alertas criticos em tempo real (socket)

`Plataforma` e o ponto unico de composicao: a API e o dashboard so conversam com ela.
"""
import hashlib
import logging
from pathlib import Path

from core import coletor, detector, enriquecimento, regras
from ia.assistente import ROTULOS, classificar_regras, texto_do_evento
from ml.anomalias import detectar_anomalias
from ml.features import extrair_features

log = logging.getLogger("securapy.analise")


class CaminhoNaoPermitido(ValueError):
    pass


class Plataforma:
    def __init__(self, settings, mongo, usuarios, classificador, assistente, blacklist,
                 transmitir=None, consultar_geo=None):
        self.settings = settings
        self.mongo = mongo                      # MongoRepo
        self.usuarios = usuarios                # UsuariosRepo
        self.classificador = classificador      # ml.classificar.Classificador
        self.assistente = assistente            # ia.assistente.Assistente
        self.blacklist = blacklist              # set
        self.transmitir = transmitir or (lambda alerta: None)
        self._cache_geo = {}
        self._consultar_geo = consultar_geo or (lambda ip: enriquecimento.consultar_ip(ip, self._cache_geo))

    # ------------------------------------------------------------ seguranca de caminho
    def resolver_pasta_logs(self, caminho=None):
        """So aceita pastas DENTRO da pasta de logs configurada (bloqueia ../ e caminhos absolutos)."""
        base = Path(self.settings.pasta_logs).resolve()
        if not caminho or caminho in (".", "logs"):
            return base
        alvo = (base / caminho).resolve()
        if alvo != base and base not in alvo.parents:
            raise CaminhoNaoPermitido("caminho fora da pasta de logs permitida")
        return alvo

    # ------------------------------------------------------------ analise
    def analisar_caminho(self, caminho=None):
        pasta = self.resolver_pasta_logs(caminho)
        eventos = coletor.carregar_todos_os_logs(str(pasta))        # pasta/arquivo inexistente -> []
        lote = "logs:" + hashlib.sha1(str(pasta).encode()).hexdigest()[:10]
        return self._analisar(eventos, lote)

    def analisar_eventos(self, eventos):
        return self._analisar(eventos, "api")

    def _analisar(self, eventos, lote):
        cfg_regras = regras.carregar_regras(str(self.settings.arquivo_regras))
        alertas_regras = regras.aplicar_regras(eventos, cfg_regras)

        brute = detector.detectar_brute_force(eventos)
        temporal = detector.detectar_brute_force_temporal(eventos)
        scan = detector.detectar_port_scan(eventos)
        bl = detector.verificar_blacklist(eventos, self.blacklist)
        ameacas = detector.gerar_resumo_ameacas(brute, scan, bl)

        feats = extrair_features(eventos, self.blacklist)
        scores = {s["ip"]: s for s in self.classificador.pontuar(feats)} if feats else {}
        anomalias = detectar_anomalias(feats)

        alertas_deteccao = [self._alerta_de_ameaca(a, scores.get(a["ip"])) for a in ameacas]
        todos = alertas_regras + alertas_deteccao

        n_eventos = self.mongo.salvar_eventos(eventos, lote=lote)
        self.mongo.salvar_alertas(alertas_regras, origem="regras", lote=lote)
        self.mongo.salvar_alertas(alertas_deteccao, origem="detector", lote=lote)

        for alerta in todos:
            if alerta["severidade"] == "CRITICA":
                self._transmitir(alerta)

        ranking = sorted(scores.values(), key=lambda s: -s["score"])
        return {
            "lote": lote,
            "eventos_processados": len(eventos), "eventos_persistidos": n_eventos,
            "alertas_regras": len(alertas_regras), "alertas_deteccao": len(alertas_deteccao),
            "alertas_criticos": sum(1 for a in todos if a["severidade"] == "CRITICA"),
            "ameacas": [{"ip": a["ip"], "deteccoes": a["deteccoes"], "pontuacao": a["pontuacao"],
                         "severidade": a["severidade"], "score_ml": scores.get(a["ip"], {}).get("score")}
                        for a in ameacas],
            "ranking_risco": [{"ip": s["ip"], "score": s["score"], "nivel": s["nivel"], "rotulo": s["rotulo"]}
                              for s in ranking],
            "correlacao_temporal": {ip: {"tentativas_pico": d["tentativas_pico"],
                                         "duracao_segundos": d["duracao_segundos"]} for ip, d in temporal.items()},
            "anomalias": anomalias,
        }

    @staticmethod
    def _alerta_de_ameaca(ameaca, score):
        extra = f" | risco ML {score['score']:.2f} ({score['nivel']})" if score else ""
        return {"timestamp": None, "regra_id": "DET-" + "+".join(d.upper() for d in ameaca["deteccoes"]),
                "regra_nome": "Ameaça correlacionada: " + ", ".join(ameaca["deteccoes"]),
                "severidade": ameaca["severidade"], "ip": ameaca["ip"],
                "descricao": f"pontuação {ameaca['pontuacao']}{extra}"}

    def _transmitir(self, alerta):
        try:
            self.transmitir({**alerta, "timestamp": alerta.get("timestamp") or ""})
        except Exception:                                  # o broadcast nunca derruba a analise
            log.exception("falha ao transmitir alerta em tempo real")

    # ------------------------------------------------------------ consulta por IP
    def detalhes_ip(self, ip):
        eventos = self.mongo.eventos_do_ip(ip)
        alertas = self.mongo.alertas_do_ip(ip)
        try:
            geo = self._consultar_geo(ip)
        except Exception:                                  # rede fora do ar nao quebra a consulta
            geo = {"ip": ip, "erro": "enriquecimento indisponível"}
        feats = extrair_features(self.mongo.todos_eventos(), self.blacklist)
        score = self.classificador.pontuar_ip(ip, feats)
        explicacao = None
        if alertas or eventos:
            # explica o item MAIS grave do IP (as regras, baratas, escolhem; o LLM so analisa 1 texto)
            amostra = max(alertas + eventos,
                          key=lambda c: ROTULOS.index(classificar_regras(texto_do_evento(c))["rotulo"]))
            explicacao = self.assistente.avaliar(amostra)
        return {"ip": ip, "eventos": eventos, "alertas": alertas, "geolocalizacao": geo,
                "score_ml": score, "explicacao": explicacao, "na_blacklist": ip in self.blacklist}

    def resumo(self):
        return {"eventos_por_fonte": self.mongo.contagem_por_fonte(),
                "alertas_por_severidade": self.mongo.contagem_por_severidade(),
                "top_ips": self.mongo.top_ips(10), "total_eventos": self.mongo.contagem_eventos()}

    def top_ips_suspeitos(self, n=10):
        """IPs com maior risco de ML entre os persistidos (para o dashboard)."""
        feats = extrair_features(self.mongo.todos_eventos(), self.blacklist)
        return self.classificador.pontuar(feats)[:n] if feats else []
