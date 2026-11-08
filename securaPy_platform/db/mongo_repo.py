"""Repositorio de eventos e alertas no MongoDB (Modulo B).

Eventos/alertas tem volume alto e schema flexivel -> documentos. Os indices em
`ip` e `timestamp` tornam as consultas por IP/periodo O(log n) em vez de varrer a colecao.
"""
from datetime import datetime, timezone

from bson import ObjectId
from bson.errors import InvalidId
from pymongo.errors import PyMongoError

FORMATO_TS = "%Y-%m-%d %H:%M:%S"
SEVERIDADES = ("INFO", "BAIXA", "MEDIA", "ALTA", "CRITICA")


class RepositorioIndisponivel(Exception):
    """O MongoDB nao respondeu (a API traduz para 503, sem vazar detalhes)."""


def _para_datetime(valor):
    if isinstance(valor, datetime):
        return valor
    return datetime.strptime(valor, FORMATO_TS)


def normalizar_severidade(valor):
    """'critica'/'Crítica'/'CRITICA' -> 'CRITICA'; devolve None se invalida."""
    if not isinstance(valor, str):
        return None
    v = valor.strip().upper().replace("Í", "I").replace("Á", "A").replace("É", "E")
    return v if v in SEVERIDADES else None


def serializar(doc):
    """ObjectId e datetime nao viram JSON: converte para string."""
    if doc is None:
        return None
    doc = dict(doc)
    doc["id"] = str(doc.pop("_id"))
    for campo in ("timestamp", "criado_em"):
        if isinstance(doc.get(campo), datetime):
            doc[campo] = doc[campo].strftime(FORMATO_TS)
    return doc


def _proteger(funcao):
    def interno(*a, **k):
        try:
            return funcao(*a, **k)
        except PyMongoError as e:
            raise RepositorioIndisponivel(type(e).__name__) from e
    interno.__name__ = funcao.__name__
    interno.__doc__ = funcao.__doc__
    return interno


class MongoRepo:
    def __init__(self, db):
        self.eventos = db.eventos
        self.alertas = db.alertas

    # ------------------------------------------------------------- indices
    @_proteger
    def garantir_indices(self):
        self.eventos.create_index("ip")
        self.eventos.create_index("timestamp")
        self.eventos.create_index([("fonte", 1), ("tipo", 1)])
        self.alertas.create_index("ip")
        self.alertas.create_index("severidade")
        self.alertas.create_index("timestamp")

    @_proteger
    def ping(self):
        self.eventos.database.client.admin.command("ping")
        return True

    # ------------------------------------------------------------- escrita
    @_proteger
    def salvar_eventos(self, eventos, lote="padrao"):
        """Substitui o lote anterior (reanalisar o mesmo log NAO duplica). Retorna a quantidade."""
        self.eventos.delete_many({"lote": lote})
        docs = []
        for e in eventos:
            try:
                docs.append({**e, "timestamp": _para_datetime(e["timestamp"]), "lote": lote})
            except (KeyError, ValueError, TypeError):
                continue                                   # evento malformado e descartado, nao derruba o lote
        if docs:
            self.eventos.insert_many(docs)
        return len(docs)

    @_proteger
    def salvar_alertas(self, alertas, origem="motor", lote="padrao"):
        self.alertas.delete_many({"lote": lote, "origem": origem})
        agora = datetime.now(timezone.utc).replace(tzinfo=None)
        docs = []
        for a in alertas:
            try:
                doc = {**a, "timestamp": _para_datetime(a.get("timestamp") or agora),
                       "origem": origem, "lote": lote, "criado_em": agora}
            except (ValueError, TypeError):
                continue
            doc["severidade"] = normalizar_severidade(doc.get("severidade")) or "INFO"
            docs.append(doc)
        if docs:
            self.alertas.insert_many(docs)
        return len(docs)

    @_proteger
    def inserir_alerta_manual(self, dados):
        agora = datetime.now(timezone.utc).replace(tzinfo=None)
        doc = {"timestamp": agora, "regra_id": dados.get("regra_id", "MANUAL"),
               "regra_nome": dados["regra_nome"], "severidade": dados["severidade"],
               "ip": dados["ip"], "descricao": dados.get("descricao", ""),
               "origem": "manual", "lote": "manual", "criado_em": agora}
        return str(self.alertas.insert_one(doc).inserted_id)

    # ------------------------------------------------------------- leitura
    @staticmethod
    def _filtro_eventos(fonte=None, tipo=None, ip=None, desde=None, ate=None):
        f = {}
        if fonte:
            f["fonte"] = fonte
        if tipo:
            f["tipo"] = tipo
        if ip:
            f["ip"] = ip
        if desde or ate:
            f["timestamp"] = {}
            if desde:
                f["timestamp"]["$gte"] = _para_datetime(desde)
            if ate:
                f["timestamp"]["$lte"] = _para_datetime(ate)
        return f

    @_proteger
    def buscar_eventos(self, fonte=None, tipo=None, ip=None, desde=None, ate=None, pagina=1, tamanho=20):
        filtro = self._filtro_eventos(fonte, tipo, ip, desde, ate)
        total = self.eventos.count_documents(filtro)
        cursor = (self.eventos.find(filtro).sort([("timestamp", 1), ("_id", 1)])
                  .skip((pagina - 1) * tamanho).limit(tamanho))
        return [serializar(d) for d in cursor], total

    @_proteger
    def buscar_alertas(self, severidade=None, ip=None, regra_id=None, pagina=1, tamanho=20):
        filtro = {}
        if severidade:
            filtro["severidade"] = severidade
        if ip:
            filtro["ip"] = ip
        if regra_id:
            filtro["regra_id"] = regra_id
        total = self.alertas.count_documents(filtro)
        cursor = (self.alertas.find(filtro).sort([("timestamp", -1), ("_id", 1)])
                  .skip((pagina - 1) * tamanho).limit(tamanho))
        return [serializar(d) for d in cursor], total

    @_proteger
    def obter_alerta(self, alerta_id):
        """Levanta ValueError para id malformado; devolve None se nao existir."""
        try:
            oid = ObjectId(alerta_id)
        except (InvalidId, TypeError):
            raise ValueError("id inválido") from None
        return serializar(self.alertas.find_one({"_id": oid}))

    @_proteger
    def eventos_do_ip(self, ip, limite=500):
        return [serializar(d) for d in self.eventos.find({"ip": ip}).sort("timestamp", 1).limit(limite)]

    @_proteger
    def alertas_do_ip(self, ip, limite=500):
        return [serializar(d) for d in self.alertas.find({"ip": ip}).sort("timestamp", 1).limit(limite)]

    # ------------------------------------------------------------- agregacoes (no banco)
    @_proteger
    def top_ips(self, n=5):
        pipeline = [{"$group": {"_id": "$ip", "total": {"$sum": 1}}},
                    {"$sort": {"total": -1, "_id": 1}}, {"$limit": n}]
        return [(d["_id"], d["total"]) for d in self.eventos.aggregate(pipeline)]

    @_proteger
    def contagem_por_severidade(self):
        pipeline = [{"$group": {"_id": "$severidade", "total": {"$sum": 1}}}]
        bruto = {d["_id"]: d["total"] for d in self.alertas.aggregate(pipeline)}
        return {s: bruto.get(s, 0) for s in reversed(SEVERIDADES)}

    @_proteger
    def contagem_por_fonte(self):
        pipeline = [{"$group": {"_id": "$fonte", "total": {"$sum": 1}}}, {"$sort": {"_id": 1}}]
        return {d["_id"]: d["total"] for d in self.eventos.aggregate(pipeline)}

    @_proteger
    def contagem_eventos(self):
        return self.eventos.count_documents({})

    @_proteger
    def todos_eventos(self):
        """Eventos no formato do nucleo (timestamp string) - usados na analise/ML por IP."""
        saida = []
        for d in self.eventos.find({}, {"_id": 0, "lote": 0}):
            d["timestamp"] = d["timestamp"].strftime(FORMATO_TS)
            saida.append(d)
        return saida
