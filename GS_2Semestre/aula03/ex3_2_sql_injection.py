"""Exercicio 3.2 - Prova de conceito DEFENSIVA de SQL Injection.

Roda apenas no MySQL local de laboratorio. Compara a busca concatenada
(vulneravel) com a parametrizada (segura) usando a entrada ' OR '1'='1.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from comum import get_mysql  # noqa: E402

from ex3_1_usuarios import USUARIOS_INICIAIS, criar_tabela  # noqa: E402

ENTRADA_MALICIOSA = "' OR '1'='1"


def buscar_inseguro(conexao, nome):
    """VULNERAVEL: a entrada vira parte do codigo SQL."""
    cur = conexao.cursor(dictionary=True)
    cur.execute(f"SELECT id, nome, email FROM usuarios WHERE nome = '{nome}'")
    return cur.fetchall()


def buscar_seguro(conexao, nome):
    """SEGURA: o driver envia 'nome' separado da query, sempre como dado."""
    cur = conexao.cursor(dictionary=True)
    cur.execute("SELECT id, nome, email FROM usuarios WHERE nome = %s", (nome,))
    return cur.fetchall()


if __name__ == "__main__":
    conn = get_mysql()
    try:
        criar_tabela(conn)
        cur = conn.cursor()
        cur.executemany("INSERT IGNORE INTO usuarios (nome, email, nivel_acesso) VALUES (%s, %s, %s)",
                        USUARIOS_INICIAIS)
        conn.commit()

        inseguros = buscar_inseguro(conn, ENTRADA_MALICIOSA)
        seguros = buscar_seguro(conn, ENTRADA_MALICIOSA)
        print(f"[INSEGURO] entrada: {ENTRADA_MALICIOSA}  -> {len(inseguros)} usuários retornados (VAZAMENTO!)")
        print(f"[SEGURO]   entrada: {ENTRADA_MALICIOSA}  -> {len(seguros)} usuários retornados (defesa OK)")
        print("Conclusão: a query parametrizada tratou a entrada como texto literal.")
    finally:
        conn.close()
