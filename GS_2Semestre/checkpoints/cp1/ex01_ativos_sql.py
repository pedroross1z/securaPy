"""CP1 - Exercicio 1: modelagem e CRUD SQL (tabela ativos, MySQL)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from comum import get_mysql  # noqa: E402

from mysql.connector import IntegrityError  # noqa: E402

ATIVOS = [
    ("SRV-WEB01", "192.168.1.10", "servidor", "alta", "ativo"),
    ("PC-RH03", "192.168.1.45", "estacao", "baixa", "ativo"),
    ("SW-CORE01", "192.168.1.1", "switch", "media", "inativo"),
]


def criar_tabela(con):
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS ativos")
    cur.execute("""
        CREATE TABLE ativos (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nome VARCHAR(100) NOT NULL,
            ip VARCHAR(45) NOT NULL UNIQUE,
            tipo VARCHAR(30) NOT NULL,
            criticidade ENUM('baixa','media','alta') NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'ativo'
        )""")
    con.commit()


def inserir(con, nome, ip, tipo, criticidade, status="ativo"):
    """Retorna (True, msg) ou (False, msg) — IP duplicado e tratado, nao estoura."""
    cur = con.cursor()
    try:
        cur.execute("INSERT INTO ativos (nome, ip, tipo, criticidade, status) "
                    "VALUES (%s, %s, %s, %s, %s)", (nome, ip, tipo, criticidade, status))
        con.commit()
    except IntegrityError:
        con.rollback()
        return False, f"Erro: IP {ip} já cadastrado (UNIQUE)"
    return True, "1 registro inserido"


def listar_por_tipo(con, tipo):
    cur = con.cursor()
    cur.execute("SELECT nome, ip, criticidade, status FROM ativos WHERE tipo = %s ORDER BY id", (tipo,))
    return cur.fetchall()


def atualizar_status(con, nome, status):
    cur = con.cursor()
    cur.execute("UPDATE ativos SET status = %s WHERE nome = %s", (status, nome))
    con.commit()
    return f"{cur.rowcount} registro atualizado" if cur.rowcount == 1 else f"{cur.rowcount} registros atualizados"


def remover(con, nome):
    cur = con.cursor()
    cur.execute("DELETE FROM ativos WHERE nome = %s", (nome,))
    con.commit()
    return f"{cur.rowcount} registro removido"


if __name__ == "__main__":
    con = get_mysql("cp1", criar=True)
    criar_tabela(con)
    for a in ATIVOS:
        inserir(con, *a)
    for nome, ip, crit, st in listar_por_tipo(con, "servidor"):
        print(f"Listar tipo='servidor' -> {nome} | {ip} | {crit} | {st}")
    print("Após UPDATE status de SW-CORE01 para 'ativo' ->", atualizar_status(con, "SW-CORE01", "ativo"))
    print("Inserir IP duplicado (192.168.1.10) ->", inserir(con, "OUTRO", "192.168.1.10", "servidor", "alta")[1])
    print("Remover PC-RH03 ->", remover(con, "PC-RH03"))
    con.close()
