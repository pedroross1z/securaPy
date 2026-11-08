"""CP1 - Exercicio 6: indice e desempenho no MongoDB."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from comum import get_mongo_db  # noqa: E402

IPS = ["185.220.101.1", "91.240.118.172", "45.33.32.156", "192.168.1.10"]


def gerar_eventos(n=1000):
    return [{"n": i, "ip": IPS[i % len(IPS)], "tipo": "FAIL" if i % 3 else "OK"} for i in range(n)]


def contar_por_ip(col, ip):
    return col.count_documents({"ip": ip})


def plano_usa_indice(col, ip):
    """True se o plano de execucao usa IXSCAN (indice) em vez de COLLSCAN (varredura)."""
    plano = col.find({"ip": ip}).explain()
    return "IXSCAN" in str(plano)


if __name__ == "__main__":
    col = get_mongo_db("cp1")["eventos_indice"]
    col.drop()
    col.insert_many(gerar_eventos())
    print(f"{col.count_documents({})} eventos inseridos.")
    t0 = time.perf_counter()
    antes = contar_por_ip(col, "185.220.101.1")
    sem = time.perf_counter() - t0
    col.create_index("ip")
    print("Índice criado em 'ip'.")
    t0 = time.perf_counter()
    depois = contar_por_ip(col, "185.220.101.1")
    com = time.perf_counter() - t0
    print(f"Eventos do IP 185.220.101.1: {depois} (antes do índice: {antes})")
    print(f"Plano usa índice (IXSCAN)? {plano_usa_indice(col, '185.220.101.1')}")
    print(f"Tempo sem índice {sem * 1000:.2f} ms | com índice {com * 1000:.2f} ms (com 1000 docs a diferença é pequena)")
    # Comentário: sem índice a busca varre a coleção inteira (O(n)); com índice a árvore B
    # localiza o IP em ~O(log n). Com milhões de eventos, é a diferença entre milissegundos e minutos.
