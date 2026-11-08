"""CP1 - Exercicio 4: query parametrizada x concatenada (defensivo, so no laboratorio local)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from comum import get_mysql  # noqa: E402

USUARIOS = [("admin", "admin@x.com"), ("ana", "ana@x.com"), ("bruno", "bruno@x.com")]
ENTRADA = "' OR '1'='1"


def preparar(con):
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS usuarios_cp1")
    cur.execute("CREATE TABLE usuarios_cp1 (id INT AUTO_INCREMENT PRIMARY KEY, "
                "nome VARCHAR(50), email VARCHAR(100))")
    cur.executemany("INSERT INTO usuarios_cp1 (nome, email) VALUES (%s, %s)", USUARIOS)
    con.commit()


def buscar_inseguro(con, nome):
    """VULNERAVEL: a entrada vira codigo SQL."""
    cur = con.cursor()
    cur.execute(f"SELECT nome, email FROM usuarios_cp1 WHERE nome = '{nome}'")
    return cur.fetchall()


def buscar_seguro(con, nome):
    """SEGURA: placeholder %s; o driver trata a entrada sempre como dado."""
    cur = con.cursor()
    cur.execute("SELECT nome, email FROM usuarios_cp1 WHERE nome = %s", (nome,))
    return cur.fetchall()


if __name__ == "__main__":
    con = get_mysql("cp1", criar=True)
    preparar(con)
    print(f"[INSEGURO] entrada={ENTRADA}  -> {len(buscar_inseguro(con, ENTRADA))} usuários (VAZAMENTO)")
    print(f"[SEGURO]   entrada={ENTRADA}  -> {len(buscar_seguro(con, ENTRADA))} usuários (defesa OK)")
    con.close()
