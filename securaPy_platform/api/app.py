"""Aplicacao Flask: API REST (/api/...) + dashboard web (/...). Modulo D.

Regras gerais: validar toda entrada (400, nunca 500), status codes semanticos, erros
internos SEM traceback/query/segredo na resposta (detalhe so no log do servidor).
"""
import ipaddress
import logging
from datetime import datetime

from flask import Blueprint, Flask, current_app, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from api.auth import emitir_token, exigir_token
from api.seguranca import LimiteTentativas, configurar_logging, registrar_seguranca
from db.mongo_repo import FORMATO_TS, RepositorioIndisponivel, normalizar_severidade
from db.mysql_repo import (BancoIndisponivel, ErroValidacao, UsuarioDuplicado, UsuarioInexistente)
from ml.classificar import ModeloAdulterado, ModeloAusente
from servicos.analise import CaminhoNaoPermitido
from settings import ConfiguracaoInvalida

log = logging.getLogger("securapy.api")
TAMANHO_MAX = 100
FONTES, TIPOS_MAX = ("auth", "firewall", "web"), 20

api = Blueprint("api", __name__, url_prefix="/api")


def plataforma():
    return current_app.config["PLATAFORMA"]


def leitura(fn):
    """Leitura e publica por padrao (conforme o enunciado); EXIGIR_AUTH_LEITURA=1 a protege."""
    def interno(*a, **k):
        if current_app.config["SETTINGS"].exigir_auth_leitura:
            return exigir_token(1)(fn)(*a, **k)
        return fn(*a, **k)
    interno.__name__ = fn.__name__
    return interno


# ------------------------------------------------------------------ validacao
class Invalido(Exception):
    pass


def _inteiro(nome, padrao, minimo, maximo=None):
    bruto = request.args.get(nome)
    if bruto is None:
        return padrao
    try:
        valor = int(bruto)
    except ValueError:
        raise Invalido(f"{nome} deve ser inteiro") from None
    if valor < minimo:
        raise Invalido(f"{nome} deve ser >= {minimo}")
    return min(valor, maximo) if maximo else valor


def paginacao():
    return _inteiro("pagina", 1, 1), _inteiro("tamanho", 20, 1, TAMANHO_MAX)


def validar_ip(ip):
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise Invalido("IP inválido") from None


def _data(nome):
    bruto = request.args.get(nome)
    if not bruto:
        return None
    for fmt in (FORMATO_TS, "%Y-%m-%d"):
        try:
            return datetime.strptime(bruto, fmt).strftime(FORMATO_TS)
        except ValueError:
            continue
    raise Invalido(f"{nome} inválido (use AAAA-MM-DD ou AAAA-MM-DD HH:MM:SS)")


def corpo_json():
    dados = request.get_json(silent=True)
    if not isinstance(dados, dict):
        raise Invalido("corpo JSON (objeto) obrigatório")
    return dados


def _texto(dados, campo, obrigatorio=True, maximo=200):
    v = dados.get(campo)
    if v is None and not obrigatorio:
        return None
    if not isinstance(v, str) or not v.strip():
        raise Invalido(f"campo '{campo}' obrigatório (texto)")
    if len(v) > maximo:
        raise Invalido(f"campo '{campo}' excede {maximo} caracteres")
    return v.strip()


def validar_alerta(dados):
    sev = normalizar_severidade(dados.get("severidade"))
    if sev is None:
        raise Invalido("severidade inválida (INFO, BAIXA, MEDIA, ALTA ou CRITICA)")
    return {"regra_nome": _texto(dados, "regra_nome", maximo=100), "severidade": sev,
            "ip": validar_ip(dados.get("ip") if isinstance(dados.get("ip"), str) else ""),
            "descricao": _texto(dados, "descricao", obrigatorio=False, maximo=500) or ""}


def validar_eventos(lista):
    if not isinstance(lista, list) or not lista:
        raise Invalido("'eventos' deve ser uma lista não vazia")
    if len(lista) > 5000:
        raise Invalido("máximo de 5000 eventos por lote")
    limpos = []
    for i, e in enumerate(lista):
        if not isinstance(e, dict):
            raise Invalido(f"evento {i} deve ser um objeto")
        for campo in ("timestamp", "fonte", "tipo", "ip", "detalhes"):
            if not isinstance(e.get(campo), str):
                raise Invalido(f"evento {i}: campo '{campo}' obrigatório (texto)")
        if e["fonte"] not in FONTES:
            raise Invalido(f"evento {i}: fonte inválida")
        try:
            datetime.strptime(e["timestamp"], FORMATO_TS)
        except ValueError:
            raise Invalido(f"evento {i}: timestamp inválido") from None
        validar_ip(e["ip"])
        limpos.append({k: e[k] for k in ("timestamp", "fonte", "tipo", "ip", "detalhes")}
                      | {"linha_original": str(e.get("linha_original", ""))[:300]})
    return limpos


def _meta(total, pagina, tamanho):
    return {"total": total, "pagina": pagina, "tamanho": tamanho,
            "paginas": (total + tamanho - 1) // tamanho}


# ------------------------------------------------------------------ rotas publicas
@api.get("/health")
def health():
    p = plataforma()
    estado = {}
    for nome, teste in (("mongo", p.mongo.ping), ("mysql", p.usuarios.ping)):
        try:
            estado[nome] = bool(teste())
        except Exception:
            estado[nome] = False
    ok = all(estado.values())
    return jsonify({"status": "ok" if ok else "degradado", **estado}), 200 if ok else 503


@api.post("/login")
def login():
    dados = corpo_json()
    email, senha = dados.get("email"), dados.get("senha")
    if not isinstance(email, str) or not isinstance(senha, str) or not email or not senha:
        raise Invalido("email e senha obrigatórios")
    limite = current_app.config["LIMITE_LOGIN_API"]
    chave = (request.remote_addr, email.strip().lower())
    if limite.bloqueado(chave):
        return jsonify({"erro": "muitas tentativas; tente mais tarde"}), 429, {"Retry-After": "300"}
    usuario = plataforma().usuarios.autenticar(email, senha)
    if not usuario:
        limite.falha(chave)
        log.warning("login falhou email=%r ip=%s", email[:80], request.remote_addr)
        return jsonify({"erro": "Credenciais inválidas"}), 401           # generica (anti-enumeracao)
    limite.sucesso(chave)
    token, exp = emitir_token(current_app.config["SETTINGS"], usuario)
    return jsonify({"token": token, "tipo": "Bearer", "expira_em": exp, "nivel": usuario["nivel_acesso"]})


# ------------------------------------------------------------------ eventos e alertas
@api.get("/eventos")
@leitura
def listar_eventos():
    pagina, tamanho = paginacao()
    fonte, tipo, ip = request.args.get("fonte"), request.args.get("tipo"), request.args.get("ip")
    if fonte and fonte not in FONTES:
        raise Invalido("fonte inválida (auth, firewall ou web)")
    if tipo and (len(tipo) > TIPOS_MAX or not tipo.isalpha()):
        raise Invalido("tipo inválido")
    if ip:
        ip = validar_ip(ip)
    itens, total = plataforma().mongo.buscar_eventos(fonte, tipo.upper() if tipo else None, ip,
                                                     _data("desde"), _data("ate"), pagina, tamanho)
    return jsonify({"itens": itens, **_meta(total, pagina, tamanho)})


@api.get("/alertas")
@leitura
def listar_alertas():
    pagina, tamanho = paginacao()
    sev = request.args.get("severidade")
    if sev and normalizar_severidade(sev) is None:
        raise Invalido("severidade inválida")
    ip = validar_ip(request.args["ip"]) if request.args.get("ip") else None
    itens, total = plataforma().mongo.buscar_alertas(normalizar_severidade(sev), ip, None, pagina, tamanho)
    return jsonify({"itens": itens, **_meta(total, pagina, tamanho)})


@api.get("/alertas/<alerta_id>")
@leitura
def obter_alerta(alerta_id):
    try:
        alerta = plataforma().mongo.obter_alerta(alerta_id)
    except ValueError:
        raise Invalido("id inválido") from None
    if alerta is None:
        return jsonify({"erro": "alerta não encontrado"}), 404
    return jsonify(alerta)


@api.post("/alertas")
@exigir_token(1)
def criar_alerta():
    alerta = validar_alerta(corpo_json())
    novo_id = plataforma().mongo.inserir_alerta_manual(alerta)
    if alerta["severidade"] == "CRITICA":
        plataforma()._transmitir({**alerta, "regra_nome": alerta["regra_nome"]})
    log.info("alerta manual criado id=%s por %s", novo_id, g.usuario["email"])
    return jsonify({"id": novo_id}), 201


# ------------------------------------------------------------------ analise e consulta por IP
@api.post("/analisar")
@exigir_token(1)
def analisar():
    dados = corpo_json() if request.data else {}
    p = plataforma()
    if "eventos" in dados:
        resumo = p.analisar_eventos(validar_eventos(dados["eventos"]))
    else:
        caminho = dados.get("caminho")
        if caminho is not None and not isinstance(caminho, str):
            raise Invalido("'caminho' deve ser texto")
        try:
            pasta = p.resolver_pasta_logs(caminho)
        except CaminhoNaoPermitido as e:
            raise Invalido(str(e)) from None
        if not pasta.is_dir():
            return jsonify({"erro": "caminho de logs não encontrado"}), 404
        resumo = p.analisar_caminho(caminho)
        if resumo["eventos_processados"] == 0:
            resumo["aviso"] = "nenhum evento válido encontrado nos logs"
    log.info("analise executada por %s: %s eventos", g.usuario["email"], resumo["eventos_processados"])
    return jsonify(resumo)


@api.get("/ip/<ip>")
@leitura
def detalhes_ip(ip):
    return jsonify(plataforma().detalhes_ip(validar_ip(ip)))


@api.get("/resumo")
@leitura
def resumo():
    return jsonify(plataforma().resumo())


@api.get("/relatorio")
@leitura
def relatorio():
    p = plataforma()
    alertas, total_alertas = p.mongo.buscar_alertas(pagina=1, tamanho=TAMANHO_MAX)
    return jsonify({"gerado_em": datetime.now().strftime(FORMATO_TS), "resumo": p.resumo(),
                    "total_alertas": total_alertas, "alertas_recentes": alertas,
                    "ranking_risco": [{k: s[k] for k in ("ip", "score", "nivel", "rotulo")}
                                      for s in p.top_ips_suspeitos(10)]})


# ------------------------------------------------------------------ administracao de usuarios (nivel 5)
@api.get("/usuarios")
@exigir_token(5)
def listar_usuarios():
    return jsonify(plataforma().usuarios.listar())


@api.post("/usuarios")
@exigir_token(5)
def criar_usuario():
    d = corpo_json()
    novo_id = plataforma().usuarios.criar(d.get("nome"), d.get("email"), d.get("senha"), d.get("nivel_acesso", 1))
    return jsonify({"id": novo_id}), 201


@api.put("/usuarios/<email>")
@exigir_token(5)
def alterar_usuario(email):
    plataforma().usuarios.alterar_nivel(email, corpo_json().get("nivel_acesso"))
    return jsonify({"mensagem": "Nível atualizado"})


@api.delete("/usuarios/<email>")
@exigir_token(5)
def remover_usuario(email):
    if email.lower() == g.usuario["email"].lower():
        raise Invalido("não é possível remover o próprio usuário")
    plataforma().usuarios.remover(email)
    return jsonify({"mensagem": "Removido"})


# ------------------------------------------------------------------ erros (sem vazar detalhes)
def _json_erro(msg, status, extra=None):
    return jsonify({"erro": msg}), status, extra or {}


def registrar_erros(app):
    @app.errorhandler(Invalido)
    def _inv(e):
        return _json_erro(str(e), 400)

    @app.errorhandler(ErroValidacao)
    def _val(e):
        return _json_erro(str(e), 400)

    @app.errorhandler(UsuarioDuplicado)
    def _dup(e):
        return _json_erro("email já cadastrado", 409)

    @app.errorhandler(UsuarioInexistente)
    def _inex(e):
        return _json_erro("usuário não encontrado", 404)

    @app.errorhandler(RepositorioIndisponivel)
    @app.errorhandler(BancoIndisponivel)
    def _indisp(e):
        log.error("dependencia indisponivel: %s", e)
        return _json_erro("serviço temporariamente indisponível", 503, {"Retry-After": "30"})

    @app.errorhandler(ModeloAdulterado)
    @app.errorhandler(ModeloAusente)
    def _modelo(e):
        log.critical("modelo de ML recusado: %s", e)
        return _json_erro("classificador indisponível", 503)

    @app.errorhandler(HTTPException)
    def _http(e):
        mensagens = {400: "requisição inválida", 404: "rota não existe", 405: "método não permitido",
                     413: "corpo grande demais", 415: "tipo de conteúdo não suportado"}
        msg = mensagens.get(e.code, e.name.lower())
        if request.path.startswith("/api"):
            return _json_erro(msg, e.code)
        return render_template("erro.html", codigo=e.code, mensagem=msg), e.code

    @app.errorhandler(Exception)
    def _geral(e):
        log.exception("erro nao tratado em %s %s", request.method, request.path)   # detalhe SO no log
        return _json_erro("erro interno", 500)


# ------------------------------------------------------------------ fabrica
def create_app(plataforma_obj):
    from web.rotas import web

    settings = plataforma_obj.settings
    if len(settings.jwt_secret) < 16 or len(settings.secret_key) < 16:
        raise ConfiguracaoInvalida("JWT_SECRET e SECRET_KEY devem ter ao menos 16 caracteres")
    configurar_logging(settings.pasta_saida)
    app = Flask(__name__, template_folder="../web/templates", static_folder="../web/static")
    app.config.update(
        PLATAFORMA=plataforma_obj, SETTINGS=settings, SECRET_KEY=settings.secret_key,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=settings.cookie_seguro, MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        JSON_SORT_KEYS=False,
        LIMITE_LOGIN_API=LimiteTentativas(), LIMITE_LOGIN_WEB=LimiteTentativas())
    app.json.ensure_ascii = False
    registrar_seguranca(app)
    registrar_erros(app)
    app.register_blueprint(api)
    app.register_blueprint(web)
    return app
