"""CP2 - Exercicio 3: retencao (TTL) e janela temporal por agregacao."""
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from comum import get_mongo_db  # noqa: E402

TTL_SEGUNDOS = 604800          # 7 dias


def preparar(col):
    col.drop()
    col.create_index("timestamp", expireAfterSeconds=TTL_SEGUNDOS)


def gerar(col, n=200, agora=None, seed=42):
    """200 eventos em 24h com pico de falhas na madrugada (horas 2-4 UTC)."""
    rnd = random.Random(seed)
    agora = agora or datetime.now(timezone.utc)
    inicio = agora - timedelta(hours=24)
    docs = []
    for _ in range(n):
        if rnd.random() < 0.55:                        # concentra parte das falhas na madrugada
            dia = (agora - timedelta(hours=rnd.randint(0, 23))).replace(hour=rnd.choice([2, 3, 3, 4]))
            ts = dia.replace(minute=rnd.randint(0, 59), second=rnd.randint(0, 59))
            if not inicio <= ts <= agora:
                ts = inicio + timedelta(seconds=rnd.randint(0, 86400))
        else:
            ts = inicio + timedelta(seconds=rnd.randint(0, 86400))
        docs.append({"timestamp": ts, "tipo": "FAIL" if rnd.random() < 0.8 else "OK",
                     "ip": f"185.220.101.{rnd.randint(1, 20)}"})
    col.insert_many(docs)
    return len(docs)


def falhas_por_hora(col, desde=None):
    filtro = {"tipo": "FAIL"}
    if desde is not None:
        filtro["timestamp"] = {"$gte": desde}
    pipeline = [{"$match": filtro},
                {"$group": {"_id": {"$hour": "$timestamp"}, "total": {"$sum": 1}}},
                {"$sort": {"_id": 1}}]
    return [(d["_id"], d["total"]) for d in col.aggregate(pipeline)]


def ttl_ativo(col):
    return any(i.get("expireAfterSeconds") == TTL_SEGUNDOS for i in col.list_indexes())


def histograma(dist):
    pico = max(dist, key=lambda x: x[1])
    linhas = [f"{h:02d}h | {'█' * max(1, t // 2)} {t}" + ("   <- pico" if (h, t) == pico else "")
              for h, t in dist]
    return "\n".join(linhas), pico


if __name__ == "__main__":
    col = get_mongo_db("cp2")["eventos"]
    preparar(col)
    print(f"{gerar(col)} eventos gerados.")
    dist = falhas_por_hora(col)
    print("=== Falhas por hora (últimas 24h) ===")
    texto, (hora, total) = histograma(dist)
    print(texto)
    print(f"Hora de pico: {hora:02d}h ({total} falhas)")
    ultimas6 = falhas_por_hora(col, datetime.now(timezone.utc) - timedelta(hours=6))
    print(f"Falhas nas últimas 6h: {sum(t for _, t in ultimas6)}")
    print("Índice TTL ativo: eventos com mais de 7 dias serão removidos automaticamente."
          if ttl_ativo(col) else "ALERTA: TTL ausente!")
    # Comentário: o TTL é decisão de segurança porque reter log para sempre amplia o vazamento
    # (LGPD/PII) e a superfície de ataque; reter pouco apaga a evidência de um incidente lento.
