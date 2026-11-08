"""Recria a tabela `usuarios` do laboratorio (rode antes de cada execucao do exploit)."""
import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from comum import get_mysql  # noqa: E402

USUARIOS = [(1, "admin", "admin@x.com", "admin-lab"), (2, "ana", "ana@x.com", "ana-lab"),
            (3, "bruno", "bruno@x.com", "bruno-lab")]


def preparar(con=None):
    con = con or get_mysql(os.environ.get("CP2_DATABASE", "cp2"), criar=True)
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS usuarios")
    cur.execute("CREATE TABLE usuarios (id INT PRIMARY KEY, nome VARCHAR(50), "
                "email VARCHAR(100), senha CHAR(64))")
    cur.executemany("INSERT INTO usuarios VALUES (%s, %s, %s, %s)",
                    [(i, n, e, hashlib.sha256(s.encode()).hexdigest()) for i, n, e, s in USUARIOS])
    con.commit()
    con.close()


if __name__ == "__main__":
    preparar()
    print("Tabela cp2.usuarios recriada (3 usuários).")
