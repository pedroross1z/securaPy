"""Controles transversais (API + dashboard): headers de seguranca, log de acesso (A09)
e limitador de tentativas de login."""
import logging
import logging.handlers
import time
from pathlib import Path

from flask import g, request

acesso = logging.getLogger("securapy.acesso")


def configurar_logging(pasta_saida=None, nivel=logging.INFO):
    """Console + arquivo rotativo para o log de acesso. Idempotente."""
    if getattr(configurar_logging, "feito", False):
        return
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    raiz = logging.getLogger("securapy")
    raiz.setLevel(nivel)
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    raiz.addHandler(console)
    if pasta_saida:
        try:
            Path(pasta_saida).mkdir(parents=True, exist_ok=True)
            arq = logging.handlers.RotatingFileHandler(Path(pasta_saida) / "acesso.log", maxBytes=1_000_000,
                                                       backupCount=3, encoding="utf-8")
            arq.setFormatter(fmt)
            raiz.addHandler(arq)
        except OSError:
            raiz.warning("nao foi possivel gravar saida/acesso.log; seguindo apenas com console")
    configurar_logging.feito = True


HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'",
}


def registrar_seguranca(app):
    """Em TODAS as respostas: 3 headers de seguranca + uma linha de log de acesso."""
    @app.before_request
    def _inicio():
        g.t0 = time.perf_counter()

    @app.after_request
    def _depois(resp):
        for nome, valor in HEADERS.items():
            resp.headers[nome] = valor
        ms = (time.perf_counter() - getattr(g, "t0", time.perf_counter())) * 1000
        usuario = getattr(g, "usuario", None)
        acesso.info("%s %s %s %s %.1fms user=%s", request.remote_addr, request.method, request.path,
                    resp.status_code, ms, usuario["email"] if usuario else "-")
        return resp


class LimiteTentativas:
    """Bloqueia uma chave (ex.: ip+email) apos `maximo` falhas dentro de `janela` segundos."""

    def __init__(self, maximo=5, janela=300, relogio=time.monotonic):
        self.maximo, self.janela, self.relogio = maximo, janela, relogio
        self._falhas = {}

    def _recentes(self, chave):
        agora = self.relogio()
        r = [t for t in self._falhas.get(chave, []) if agora - t < self.janela]
        self._falhas[chave] = r
        return r

    def bloqueado(self, chave):
        return len(self._recentes(chave)) >= self.maximo

    def falha(self, chave):
        self._recentes(chave).append(self.relogio())

    def sucesso(self, chave):
        self._falhas.pop(chave, None)
