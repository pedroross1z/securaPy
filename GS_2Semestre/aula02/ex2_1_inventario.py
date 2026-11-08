"""Exercicio 2.1 - CRUD de inventario de ativos no MongoDB (com menu)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from comum import get_mongo_db  # noqa: E402

from pymongo.errors import DuplicateKeyError  # noqa: E402

ATIVOS_INICIAIS = [
    {"nome": "SRV-WEB01", "tipo": "servidor", "ip": "192.168.1.10", "status": "ativo"},
    {"nome": "PC-RH03", "tipo": "estacao", "ip": "192.168.1.45", "status": "ativo"},
    {"nome": "SW-CORE01", "tipo": "switch", "ip": "192.168.1.1", "status": "inativo"},
]


def preparar(colecao):
    """Garante o indice unico de IP (impede duplicados) e popula a colecao vazia."""
    colecao.create_index("ip", unique=True)
    if colecao.count_documents({}) == 0:
        colecao.insert_many([dict(a) for a in ATIVOS_INICIAIS])


def cadastrar(colecao, nome, tipo, ip, status="ativo"):
    try:
        colecao.insert_one({"nome": nome, "tipo": tipo, "ip": ip, "status": status})
    except DuplicateKeyError:
        return "Erro: IP já cadastrado!"
    return "Ativo cadastrado!"


def listar(colecao):
    return list(colecao.find({}, {"_id": 0}).sort("ip", 1))


def buscar_por_ip(colecao, ip):
    return colecao.find_one({"ip": ip}, {"_id": 0})


def atualizar_status(colecao, ip, status):
    r = colecao.update_one({"ip": ip}, {"$set": {"status": status}})
    return "Status atualizado!" if r.matched_count else "Erro: IP não encontrado"


def remover(colecao, ip):
    r = colecao.delete_one({"ip": ip})
    return "Ativo removido!" if r.deleted_count else "Erro: IP não encontrado"


def exibir_tabela(ativos):
    print(f"{'NOME':<12} {'TIPO':<10} {'IP':<15} STATUS")
    for a in ativos:
        print(f"{a['nome']:<12} {a['tipo']:<10} {a['ip']:<15} {a['status']}")
    print(f"Total: {len(ativos)} ativos")


def menu(colecao):
    while True:
        print("\n[1] Cadastrar  [2] Listar  [3] Buscar por IP  "
              "[4] Atualizar status  [5] Remover  [6] Sair")
        op = input("Opção: ").strip()
        if op == "1":
            print(cadastrar(colecao, input("Nome: "), input("Tipo: "), input("IP: ").strip()))
        elif op == "2":
            exibir_tabela(listar(colecao))
        elif op == "3":
            a = buscar_por_ip(colecao, input("IP: ").strip())
            print(a if a else "Ativo não encontrado")
        elif op == "4":
            print(atualizar_status(colecao, input("IP: ").strip(), input("Novo status: ").strip()))
        elif op == "5":
            print(remover(colecao, input("IP: ").strip()))
        elif op == "6":
            break
        else:
            print("Opção inválida")


if __name__ == "__main__":
    colecao = get_mongo_db()["ativos"]
    preparar(colecao)
    menu(colecao)
