"""Repositorio de usuarios/operadores no MySQL (Modulo B).

Usuarios e permissoes pedem integridade relacional (UNIQUE, CHECK, transacao) -> MySQL.
TODAS as queries sao parametrizadas (%s): a entrada do usuario nunca vira SQL.
"""
import mysql.connector
from werkzeug.security import check_password_hash, generate_password_hash

NIVEL_MIN, NIVEL_MAX = 1, 5
# hash de uma senha qualquer: comparado quando o e-mail nao existe, para que o tempo de
# resposta nao revele se o usuario existe (anti-enumeracao, OWASP A07)
_HASH_FALSO = generate_password_hash("senha-inexistente-para-igualar-o-tempo")


class UsuarioDuplicado(Exception):
    pass


class UsuarioInexistente(Exception):
    pass


class ErroValidacao(ValueError):
    pass


class BancoIndisponivel(Exception):
    """MySQL fora do ar / erro de infraestrutura (a API responde 503 generico)."""


def validar_nivel(nivel):
    if isinstance(nivel, bool) or not isinstance(nivel, int) or not NIVEL_MIN <= nivel <= NIVEL_MAX:
        raise ErroValidacao(f"nível de acesso deve ser inteiro de {NIVEL_MIN} a {NIVEL_MAX}")
    return nivel


def validar_email(email):
    if not isinstance(email, str) or "@" not in email or len(email) > 150 or email != email.strip():
        raise ErroValidacao("email inválido")
    return email.lower()


class UsuariosRepo:
    def __init__(self, conexao_factory):
        self._factory = conexao_factory

    def _executar(self, fn):
        try:
            con = self._factory()
        except mysql.connector.Error as e:
            raise BancoIndisponivel(type(e).__name__) from e
        try:
            return fn(con)
        except (mysql.connector.IntegrityError, UsuarioDuplicado, UsuarioInexistente, ErroValidacao):
            raise
        except mysql.connector.Error as e:
            raise BancoIndisponivel(type(e).__name__) from e
        finally:
            con.close()

    def criar_tabelas(self):
        def f(con):
            con.cursor().execute("""
                CREATE TABLE IF NOT EXISTS usuarios (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    nome VARCHAR(100) NOT NULL,
                    email VARCHAR(150) NOT NULL UNIQUE,
                    senha_hash VARCHAR(255) NOT NULL,
                    nivel_acesso INT NOT NULL DEFAULT 1,
                    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT chk_nivel CHECK (nivel_acesso BETWEEN 1 AND 5)
                ) ENGINE=InnoDB""")
            con.commit()
        self._executar(f)

    def ping(self):
        self._executar(lambda con: con.cursor().execute("SELECT 1") or True)
        return True

    # ------------------------------------------------------------------ CRUD
    def criar(self, nome, email, senha, nivel=1):
        if not isinstance(nome, str) or not nome.strip():
            raise ErroValidacao("nome obrigatório")
        email = validar_email(email)
        validar_nivel(nivel)
        if not isinstance(senha, str) or len(senha) < 8:
            raise ErroValidacao("senha deve ter ao menos 8 caracteres")

        def f(con):
            cur = con.cursor()
            try:
                cur.execute("INSERT INTO usuarios (nome, email, senha_hash, nivel_acesso) "
                            "VALUES (%s, %s, %s, %s)",
                            (nome.strip(), email, generate_password_hash(senha), nivel))
                con.commit()
            except mysql.connector.IntegrityError:
                con.rollback()
                raise UsuarioDuplicado(email) from None
            return cur.lastrowid
        return self._executar(f)

    def listar(self):
        def f(con):
            cur = con.cursor(dictionary=True)
            cur.execute("SELECT id, nome, email, nivel_acesso FROM usuarios ORDER BY id")
            return cur.fetchall()
        return self._executar(f)

    def buscar_por_email(self, email):
        def f(con):
            cur = con.cursor(dictionary=True)
            cur.execute("SELECT id, nome, email, nivel_acesso FROM usuarios WHERE email = %s", (email.lower(),))
            return cur.fetchone()
        return self._executar(f)

    def alterar_nivel(self, email, nivel):
        validar_nivel(nivel)

        def f(con):
            cur = con.cursor()
            cur.execute("UPDATE usuarios SET nivel_acesso = %s WHERE email = %s", (nivel, email.lower()))
            con.commit()
            if cur.rowcount == 0:
                cur.execute("SELECT 1 FROM usuarios WHERE email = %s", (email.lower(),))
                if cur.fetchone() is None:
                    raise UsuarioInexistente(email)
            return True
        return self._executar(f)

    def remover(self, email):
        def f(con):
            cur = con.cursor()
            cur.execute("DELETE FROM usuarios WHERE email = %s", (email.lower(),))
            con.commit()
            if cur.rowcount == 0:
                raise UsuarioInexistente(email)
            return True
        return self._executar(f)

    # ------------------------------------------------------------------ autenticacao
    def autenticar(self, email, senha):
        """Retorna o usuario (sem hash) ou None. Mesmo caminho para 'nao existe' e 'senha errada'."""
        if not isinstance(email, str) or not isinstance(senha, str):
            return None

        def f(con):
            cur = con.cursor(dictionary=True)
            cur.execute("SELECT id, nome, email, nivel_acesso, senha_hash FROM usuarios WHERE email = %s",
                        (email.strip().lower(),))
            return cur.fetchone()
        linha = self._executar(f)
        ok = check_password_hash(linha["senha_hash"] if linha else _HASH_FALSO, senha)
        if not linha or not ok:
            return None
        linha.pop("senha_hash")
        return linha
