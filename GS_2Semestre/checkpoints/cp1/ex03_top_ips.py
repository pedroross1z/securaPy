"""CP1 - Exercicio 3: aggregation pipeline - top IPs com mais FAIL."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from comum import get_mongo_db  # noqa: E402

EVENTOS = [
    {"tipo": "FAIL", "ip": "185.220.101.1"}, {"tipo": "FAIL", "ip": "185.220.101.1"},
    {"tipo": "OK", "ip": "192.168.1.10"}, {"tipo": "FAIL", "ip": "91.240.118.172"},
    {"tipo": "FAIL", "ip": "185.220.101.1"}, {"tipo": "FAIL", "ip": "91.240.118.172"},
    {"tipo": "FAIL", "ip": "45.33.32.156"}, {"tipo": "FAIL", "ip": "185.220.101.1"},
]


def top_ips_fail(col, n=3):
    """A contagem e o ranking acontecem no banco, nao num laco Python."""
    pipeline = [
        {"$match": {"tipo": "FAIL"}},
        {"$group": {"_id": "$ip", "total": {"$sum": 1}}},
        {"$sort": {"total": -1, "_id": 1}},          # _id desempata de forma deterministica
        {"$limit": n},
    ]
    return [(d["_id"], d["total"]) for d in col.aggregate(pipeline)]


if __name__ == "__main__":
    col = get_mongo_db("cp1")["eventos_top"]
    col.delete_many({})
    col.insert_many([dict(e) for e in EVENTOS])
    for ip, total in top_ips_fail(col):
        print(f"{ip} -> {total}")
