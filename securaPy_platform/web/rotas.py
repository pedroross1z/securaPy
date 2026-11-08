"""Dashboard web (Modulo E).

Defesas: Jinja2 com autoescape (nada de |safe), headers de seguranca (registrar_seguranca),
CSRF em todo POST, cookie de sessao HttpOnly + SameSite, login com mensagem generica e
limite de tentativas, senha so como hash, log de acesso de cada requisicao (A09).
"""
import functools
import hmac
import logging
import secrets

from flask import (Blueprint, current_app, flash, redirect, render_template, request,
                   session, url_for)

from api.app import Invalido, validar_alerta, validar_ip
from db.mongo_repo import SEVERIDADES

log = logging.getLogger("securapy.web")
web = Blueprint("web", __name__)


def plataforma():
    return current_app.config["PLATAFORMA"]


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


@web.app_context_processor
def _contexto():
    return {"csrf_token": csrf_token, "usuario": session.get("usuario")}


def exige_csrf():
    enviado = request.form.get("csrf", "")
    if not enviado or not hmac.compare_digest(enviado, session.get("csrf", "")):
        return render_template("erro.html", codigo=400, mensagem="requisição inválida (CSRF)"), 400
    return None


def login_obrigatorio(nivel_minimo=1):
    def deco(fn):
        @functools.wraps(fn)
        def interno(*a, **k):
            u = session.get("usuario")
            if not u:
                return redirect(url_for("web.login"))
            if u["nivel"] < nivel_minimo:
                return render_template("erro.html", codigo=403, mensagem="acesso negado"), 403
            return fn(*a, **k)
        return interno
    return deco


@web.get("/")
def raiz():
    return redirect(url_for("web.dashboard" if session.get("usuario") else "web.login"))


@web.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    negado = exige_csrf()
    if negado:
        return negado
    email, senha = request.form.get("email", "").strip(), request.form.get("senha", "")
    if not email or not senha:
        return render_template("login.html", erro="Informe e-mail e senha."), 400
    limite = current_app.config["LIMITE_LOGIN_WEB"]
    chave = (request.remote_addr, email.lower())
    if limite.bloqueado(chave):
        return render_template("login.html", erro="Muitas tentativas. Tente novamente mais tarde."), 429
    usuario = plataforma().usuarios.autenticar(email, senha)
    if not usuario:
        limite.falha(chave)
        log.warning("login web falhou email=%r ip=%s", email[:80], request.remote_addr)
        # mesma mensagem para "usuario nao existe" e "senha errada" (anti-enumeracao, A07)
        return render_template("login.html", erro="Credenciais inválidas."), 401
    limite.sucesso(chave)
    session.clear()                                         # novo id de sessao: evita session fixation
    session["usuario"] = {"email": usuario["email"], "nome": usuario["nome"], "nivel": usuario["nivel_acesso"]}
    csrf_token()
    return redirect(url_for("web.dashboard"))


@web.post("/logout")
def logout():
    negado = exige_csrf()
    if negado:
        return negado
    session.clear()
    return redirect(url_for("web.login"))


@web.get("/dashboard")
@login_obrigatorio()
def dashboard():
    p = plataforma()
    alertas, _ = p.mongo.buscar_alertas(pagina=1, tamanho=10)
    return render_template("dashboard.html", resumo=p.resumo(), suspeitos=p.top_ips_suspeitos(10),
                           alertas=alertas, severidades=SEVERIDADES)


@web.get("/ip")
@login_obrigatorio()
def buscar_ip():
    try:
        ip = validar_ip(request.args.get("q", "").strip())
    except Invalido:
        flash("IP inválido.")
        return redirect(url_for("web.dashboard"))
    return redirect(url_for("web.pagina_ip", ip=ip))


@web.get("/ip/<ip>")
@login_obrigatorio()
def pagina_ip(ip):
    try:
        ip = validar_ip(ip)
    except Invalido:
        return render_template("erro.html", codigo=400, mensagem="IP inválido"), 400
    return render_template("ip.html", d=plataforma().detalhes_ip(ip))


@web.post("/alertas")
@login_obrigatorio()
def novo_alerta():
    negado = exige_csrf()
    if negado:
        return negado
    try:
        alerta = validar_alerta({k: request.form.get(k, "") for k in ("regra_nome", "severidade", "ip", "descricao")})
    except Invalido as e:
        flash(f"Alerta não cadastrado: {e}")
        return redirect(url_for("web.dashboard")), 303
    plataforma().mongo.inserir_alerta_manual(alerta)
    flash("Alerta cadastrado.")
    return redirect(url_for("web.dashboard"))


@web.post("/analisar")
@login_obrigatorio(1)
def executar_analise():
    negado = exige_csrf()
    if negado:
        return negado
    r = plataforma().analisar_caminho()
    flash(f"Análise concluída: {r['eventos_persistidos']} eventos, "
          f"{r['alertas_regras'] + r['alertas_deteccao']} alertas.")
    return redirect(url_for("web.dashboard"))
