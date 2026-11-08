"""CP1 - Exercicio 5: transacao com rollback (transferencia entre contas)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from comum import get_mysql  # noqa: E402

import mysql.connector  # noqa: E402


class ContaInexistente(Exception):
    pass


def preparar(con):
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS contas")
    cur.execute("CREATE TABLE contas (id INT PRIMARY KEY, titular VARCHAR(50), "
                "saldo DECIMAL(12,2) NOT NULL CHECK (saldo >= 0)) ENGINE=InnoDB")
    cur.executemany("INSERT INTO contas VALUES (%s, %s, %s)", [(1, "Alice", 1000), (2, "Bob", 500)])
    con.commit()


def saldo(con, conta_id):
    cur = con.cursor()
    cur.execute("SELECT saldo FROM contas WHERE id = %s", (conta_id,))
    linha = cur.fetchone()
    return float(linha[0]) if linha else None


def transferir(con, origem, destino, valor):
    """Debita e credita na MESMA transacao: ou as duas acontecem, ou nenhuma."""
    cur = con.cursor()
    try:
        cur.execute("UPDATE contas SET saldo = saldo - %s WHERE id = %s", (valor, origem))
        if cur.rowcount != 1:
            raise ContaInexistente(f"conta origem {origem} inexistente")
        cur.execute("UPDATE contas SET saldo = saldo + %s WHERE id = %s", (valor, destino))
        if cur.rowcount != 1:
            raise ContaInexistente(f"conta destino {destino} inexistente")
        con.commit()
        return True
    except (ContaInexistente, mysql.connector.Error):
        con.rollback()                  # desfaz o debito ja executado
        return False


if __name__ == "__main__":
    con = get_mysql("cp1", criar=True)
    preparar(con)
    ok = transferir(con, 1, 2, 200)
    print(f"Transferência 1 {'OK' if ok else 'FALHOU'}. Alice={saldo(con, 1):.0f}, Bob={saldo(con, 2):.0f}")
    ok = transferir(con, 1, 99, 100)
    print("Transferência 2 " + ("OK." if ok else "FALHOU (conta destino inexistente). Rollback.")
          + f" Alice={saldo(con, 1):.0f}")
    con.close()
