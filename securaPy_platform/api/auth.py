"""Autenticacao por token JWT (HS256) - Modulo D + bonus "JWT completo" (geracao e verificacao).

Seguranca: o algoritmo aceito e FIXO (algorithms=["HS256"]) - nunca o que vem no header do token
(evita o ataque de confusao de algoritmo / alg=none); `exp`, `iat`, `iss` e `sub` sao exigidos.
"""
import functools
import time

import jwt
from flask import current_app, g, jsonify, request

ALGORITMO = "HS256"
ISSUER = "securapy"


class TokenInvalido(Exception):
    pass


def emitir_token(settings, usuario, agora=None):
    agora = int(agora if agora is not None else time.time())
    claims = {"sub": usuario["email"], "uid": usuario["id"], "nivel": usuario["nivel_acesso"],
              "iat": agora, "exp": agora + settings.jwt_ttl_segundos, "iss": ISSUER}
    return jwt.encode(claims, settings.jwt_secret, algorithm=ALGORITMO), claims["exp"]


def verificar_token(settings, token):
    try:
        claims = jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITMO], issuer=ISSUER,
                            options={"require": ["exp", "iat", "iss", "sub"]})
    except jwt.PyJWTError as e:
        raise TokenInvalido(type(e).__name__) from None
    nivel = claims.get("nivel")
    if isinstance(nivel, bool) or not isinstance(nivel, int):
        raise TokenInvalido("nivel invalido")
    return {"email": claims["sub"], "id": claims.get("uid"), "nivel_acesso": nivel}


def _token_do_header():
    h = request.headers.get("Authorization", "")
    partes = h.split(None, 1)
    if len(partes) == 2 and partes[0].lower() == "bearer":
        return partes[1].strip()
    return ""


def exigir_token(nivel_minimo=1):
    """Decorator: 401 sem token valido; 403 se o nivel for insuficiente."""
    def deco(fn):
        @functools.wraps(fn)
        def interno(*a, **k):
            token = _token_do_header()
            if not token:
                return jsonify({"erro": "autenticação necessária"}), 401, {"WWW-Authenticate": "Bearer"}
            try:
                g.usuario = verificar_token(current_app.config["SETTINGS"], token)
            except TokenInvalido:
                return jsonify({"erro": "token inválido ou expirado"}), 401, {"WWW-Authenticate": "Bearer"}
            if g.usuario["nivel_acesso"] < nivel_minimo:
                return jsonify({"erro": "acesso negado"}), 403
            return fn(*a, **k)
        return interno
    return deco
