"""CP1 - Exercicio 2: CRUD com PyMongo (colecao vulnerabilidades)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from comum import get_mongo_db  # noqa: E402

VULNS = [
    {"cve_id": "CVE-2024-001", "tipo": "SQL Injection", "severidade": "Alta", "corrigida": False},
    {"cve_id": "CVE-2024-002", "tipo": "XSS", "severidade": "Media", "corrigida": True},
    {"cve_id": "CVE-2024-003", "tipo": "Path Traversal", "severidade": "Critica", "corrigida": False},
]


def popular(col):
    col.delete_many({})
    col.insert_many([dict(v) for v in VULNS])
    col.create_index("cve_id", unique=True)


def buscar_por_severidade(col, severidade):
    return list(col.find({"severidade": severidade}, {"_id": 0}))


def marcar_corrigida(col, cve_id):
    r = col.update_one({"cve_id": cve_id}, {"$set": {"corrigida": True}})
    return f"{r.modified_count} documento modificado"


def remover(col, cve_id):
    return col.delete_one({"cve_id": cve_id}).deleted_count


def abertas(col):
    return col.count_documents({"corrigida": False})


if __name__ == "__main__":
    col = get_mongo_db("cp1")["vulnerabilidades"]
    popular(col)
    for v in buscar_por_severidade(col, "Alta"):
        print(f"Buscar severidade='Alta' -> {v['cve_id']}: {v['tipo']}")
    print("update corrigida=True em 001 ->", marcar_corrigida(col, "CVE-2024-001"))
    print("count corrigida=False ->", abertas(col), "(só a CVE-2024-003 restou aberta)")
    print("delete CVE-2024-002 ->", remover(col, "CVE-2024-002"), "documento removido")
