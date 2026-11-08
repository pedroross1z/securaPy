"""Exercicio 3.1 - CRUD de usuarios e permissoes no MySQL (100% parametrizado)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from comum import get_mysql  # noqa: E402

from mysql.connector import Error, IntegrityError  # noqa: E402

USUARIOS_INICIAIS = [
    ("Carlos Silva", "carlos@empresa.com", 3),
    ("Ana Costa", "ana@empresa.com", 5),
    ("Bruno Lima", "bruno@empresa.com", 1),
]


def criar_tabela(conexao):
    cur = conexao.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nome VARCHAR(100) NOT NULL,
            email VARCHAR(150) NOT NULL UNIQUE,
            nivel_acesso INT NOT NULL DEFAULT 1,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT chk_nivel CHECK (nivel_acesso BETWEEN 1 AND 5)
        )
    """)
    conexao.commit()


def nivel_valido(nivel):
    return isinstance(nivel, int) and 1 <= nivel <= 5


def cadastrar(conexao, nome, email, nivel):
    if not nivel_valido(nivel):
        return "Erro: nível deve estar entre 1 e 5"
    cur = conexao.cursor()
    try:
        cur.execute("INSERT INTO usuarios (nome, email, nivel_acesso) VALUES (%s, %s, %s)",
                    (nome, email, nivel))
        conexao.commit()
    except IntegrityError:
        conexao.rollback()
        return "Erro: email já existe"
    return "Usuário cadastrado!"


def listar(conexao):
    cur = conexao.cursor(dictionary=True)
    cur.execute("SELECT id, nome, email, nivel_acesso FROM usuarios ORDER BY id")
    return cur.fetchall()


def buscar_por_email(conexao, email):
    cur = conexao.cursor(dictionary=True)
    cur.execute("SELECT id, nome, email, nivel_acesso FROM usuarios WHERE email = %s", (email,))
    return cur.fetchone()


def alterar_nivel(conexao, email, novo_nivel):
    if not nivel_valido(novo_nivel):
        return "Erro: nível deve estar entre 1 e 5"
    cur = conexao.cursor()
    cur.execute("UPDATE usuarios SET nivel_acesso = %s WHERE email = %s", (novo_nivel, email))
    conexao.commit()
    return "Nível atualizado!" if cur.rowcount else "Erro: usuário não encontrado"


def remover(conexao, email):
    cur = conexao.cursor()
    cur.execute("DELETE FROM usuarios WHERE email = %s", (email,))
    conexao.commit()
    return "Usuário removido!" if cur.rowcount else "Erro: usuário não encontrado"


def exibir(usuarios):
    for u in usuarios:
        print(f"{u['nome']:<13}| {u['email']:<19}| nível {u['nivel_acesso']}")


def menu(conexao):
    while True:
        print("\n[1] Cadastrar [2] Listar [3] Buscar por email "
              "[4] Promover/rebaixar [5] Remover [6] Sair")
        op = input("Opção: ").strip()
        try:
            if op == "1":
                print(cadastrar(conexao, input("Nome: "), input("Email: ").strip(),
                                int(input("Nível (1-5): "))))
            elif op == "2":
                exibir(listar(conexao))
            elif op == "3":
                u = buscar_por_email(conexao, input("Email: ").strip())
                exibir([u]) if u else print("Usuário não encontrado")
            elif op == "4":
                print(alterar_nivel(conexao, input("Email: ").strip(), int(input("Novo nível: "))))
            elif op == "5":
                print(remover(conexao, input("Email: ").strip()))
            elif op == "6":
                break
            else:
                print("Opção inválida")
        except ValueError:
            print("Erro: informe um número inteiro para o nível")
        except Error as e:
            print(f"Erro de banco: {e.msg}")


if __name__ == "__main__":
    conn = get_mysql()
    try:
        criar_tabela(conn)
        cur = conn.cursor()
        cur.executemany("INSERT IGNORE INTO usuarios (nome, email, nivel_acesso) VALUES (%s, %s, %s)",
                        USUARIOS_INICIAIS)
        conn.commit()
        menu(conn)
    finally:
        conn.close()
