"""Exercicios 7.1 e 7.2 - API de incidentes com Flask + MongoDB.

7.1  CRUD completo, serializacao de _id e validacao de campos obrigatorios.
7.2  Paginacao, filtros e ordenacao.

Parametros aceitos em GET /api/incidentes
    pagina      int >= 1          (padrao 1)
    tamanho     int 1..100        (padrao 10)
    severidade  baixa|media|alta|critica
    status      aberto|em_andamento|resolvido
    O resultado e sempre ordenado por criado_em, do mais recente ao mais antigo.
    O total de registros (apos filtros) vai no header X-Total-Count.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from comum import get_mongo_db  # noqa: E402

from bson import ObjectId  # noqa: E402
from bson.errors import InvalidId  # noqa: E402
from flask import Flask, jsonify, request  # noqa: E402

SEVERIDADES = ("baixa", "media", "alta", "critica")
STATUS = ("aberto", "em_andamento", "resolvido")
CAMPOS_EDITAVEIS = ("titulo", "severidade", "status", "ip_origem")


def serializar(doc):
    """ObjectId e datetime nao viram JSON sozinhos: converte para string."""
    doc = dict(doc)
    doc["_id"] = str(doc["_id"])
    if isinstance(doc.get("criado_em"), datetime):
        doc["criado_em"] = doc["criado_em"].isoformat()
    return doc


def validar(dados, parcial=False):
    if not isinstance(dados, dict):
        return "corpo JSON obrigatório"
    if not parcial:
        faltando = [c for c in ("titulo", "severidade") if not dados.get(c)]
        if faltando:
            return f"campos obrigatórios: {', '.join(faltando)}"
    if "titulo" in dados and (not isinstance(dados["titulo"], str) or not dados["titulo"].strip()):
        return "titulo inválido"
    if "severidade" in dados and dados["severidade"] not in SEVERIDADES:
        return f"severidade inválida (use {', '.join(SEVERIDADES)})"
    if "status" in dados and dados["status"] not in STATUS:
        return f"status inválido (use {', '.join(STATUS)})"
    if "ip_origem" in dados and not isinstance(dados["ip_origem"], str):
        return "ip_origem inválido"
    return None


def create_app(db=None):
    app = Flask(__name__)
    if db is None:
        db = get_mongo_db()
    col = db.incidentes

    def para_oid(id):
        try:
            return ObjectId(id)
        except (InvalidId, TypeError):
            return None

    @app.post("/api/incidentes")
    def criar():
        dados = request.get_json(silent=True)
        erro = validar(dados)
        if erro:
            return jsonify({"erro": erro}), 400
        doc = {k: dados[k] for k in CAMPOS_EDITAVEIS if k in dados}
        doc.setdefault("status", "aberto")
        doc["criado_em"] = datetime.now(timezone.utc)
        return jsonify({"id": str(col.insert_one(doc).inserted_id)}), 201

    @app.get("/api/incidentes")
    def listar():
        try:
            pagina = int(request.args.get("pagina", 1))
            tamanho = int(request.args.get("tamanho", 10))
        except ValueError:
            return jsonify({"erro": "pagina e tamanho devem ser inteiros"}), 400
        if pagina < 1 or not 1 <= tamanho <= 100:
            return jsonify({"erro": "pagina >= 1 e tamanho entre 1 e 100"}), 400

        filtro = {}
        for campo, validos in (("severidade", SEVERIDADES), ("status", STATUS)):
            valor = request.args.get(campo)
            if valor is not None:
                if valor not in validos:       # valor literal: nada de operadores ($ne, $gt...)
                    return jsonify({"erro": f"{campo} inválido"}), 400
                filtro[campo] = valor

        cursor = (col.find(filtro).sort("criado_em", -1)
                  .skip((pagina - 1) * tamanho).limit(tamanho))
        resp = jsonify([serializar(d) for d in cursor])
        resp.headers["X-Total-Count"] = str(col.count_documents(filtro))
        return resp

    @app.get("/api/incidentes/<id>")
    def obter(id):
        oid = para_oid(id)
        if oid is None:
            return jsonify({"erro": "id inválido"}), 400
        doc = col.find_one({"_id": oid})
        if not doc:
            return jsonify({"erro": "não encontrado"}), 404
        return jsonify(serializar(doc))

    @app.put("/api/incidentes/<id>")
    def atualizar(id):
        oid = para_oid(id)
        if oid is None:
            return jsonify({"erro": "id inválido"}), 400
        dados = request.get_json(silent=True)
        erro = validar(dados, parcial=True)
        if erro:
            return jsonify({"erro": erro}), 400
        campos = {k: dados[k] for k in CAMPOS_EDITAVEIS if k in dados}   # whitelist
        if not campos:
            return jsonify({"erro": "nenhum campo para atualizar"}), 400
        if col.update_one({"_id": oid}, {"$set": campos}).matched_count == 0:
            return jsonify({"erro": "não encontrado"}), 404
        return jsonify(serializar(col.find_one({"_id": oid})))

    @app.delete("/api/incidentes/<id>")
    def remover(id):
        oid = para_oid(id)
        if oid is None:
            return jsonify({"erro": "id inválido"}), 400
        if col.delete_one({"_id": oid}).deleted_count == 0:
            return jsonify({"erro": "não encontrado"}), 404
        return jsonify({"mensagem": "Removido"}), 200

    @app.errorhandler(404)
    def rota_inexistente(e):
        return jsonify({"erro": "Rota não existe"}), 404

    @app.errorhandler(500)
    def erro_interno(e):
        return jsonify({"erro": "Erro interno do servidor"}), 500

    return app


def popular(db, quantidade=15):
    """Insere incidentes variados com datas distintas (para testar 7.2)."""
    from datetime import timedelta
    base = datetime.now(timezone.utc)
    docs = []
    for i in range(quantidade):
        docs.append({
            "titulo": f"Incidente {i + 1:02d}",
            "severidade": SEVERIDADES[i % 4],
            "status": STATUS[i % 3],
            "ip_origem": f"185.220.101.{i + 1}",
            "criado_em": base - timedelta(minutes=quantidade - i),
        })
    db.incidentes.insert_many(docs)
    return len(docs)


if __name__ == "__main__":
    banco = get_mongo_db()
    if banco.incidentes.count_documents({}) == 0:
        print(f"Populando {popular(banco)} incidentes de exemplo...")
    create_app(banco).run(port=5000, debug=False)
