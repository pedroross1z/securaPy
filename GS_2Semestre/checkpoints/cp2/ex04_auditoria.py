"""CP2 - Exercicio 4: transacao MySQL + trilha de auditoria no Mongo (A09).

Regra de ouro: a tentativa e registrada SEMPRE (finally), inclusive as recusadas e
as que falham por erro; sem rastro, o ataque e invisivel. Se nem a auditoria puder
ser gravada, a alteracao NAO e confirmada (fail closed): privilegio sem trilha e proibido.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from comum import get_mongo_db, get_mysql  # noqa: E402

NIVEL_ADMIN = 5
USUARIOS = [(1, "ana", "ana@x.com", 5), (2, "bruno", "bruno@x.com", 2), (3, "caio", "caio@x.com", 1)]


def preparar(con):
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS usuarios_aud")
    cur.execute("""CREATE TABLE usuarios_aud (
        id INT PRIMARY KEY, nome VARCHAR(50), email VARCHAR(100) UNIQUE,
        nivel_acesso INT NOT NULL CHECK (nivel_acesso BETWEEN 1 AND 5)) ENGINE=InnoDB""")
    cur.executemany("INSERT INTO usuarios_aud VALUES (%s, %s, %s, %s)", USUARIOS)
    con.commit()


def _nivel(cur, uid):
    cur.execute("SELECT nivel_acesso FROM usuarios_aud WHERE id = %s FOR UPDATE", (uid,))
    linha = cur.fetchone()
    return linha[0] if linha else None


def alterar_nivel(con, auditoria, admin_id, alvo_id, novo_nivel):
    """Retorna (resultado, motivo). resultado: 'ACEITO' | 'RECUSADO'."""
    anterior, resultado, motivo = None, "RECUSADO", ""
    cur = con.cursor()
    try:
        con.rollback()                                   # garante transacao limpa
        nivel_admin = _nivel(cur, admin_id)
        anterior = _nivel(cur, alvo_id)
        if nivel_admin is None or nivel_admin < NIVEL_ADMIN:
            motivo = "admin sem privilégio"
        elif admin_id == alvo_id:
            motivo = "auto-promoção"
        elif not isinstance(novo_nivel, int) or isinstance(novo_nivel, bool) or not 1 <= novo_nivel <= 5:
            motivo = "nível inválido (1 a 5)"
        elif anterior is None:
            motivo = "alvo inexistente"
        else:
            cur.execute("UPDATE usuarios_aud SET nivel_acesso = %s WHERE id = %s", (novo_nivel, alvo_id))
            resultado = "ACEITO"
        if resultado == "ACEITO":
            _gravar(auditoria, admin_id, alvo_id, anterior, novo_nivel, resultado, "")  # antes do commit
            con.commit()
        else:
            con.rollback()
    except Exception as e:                                # qualquer falha: desfaz e recusa
        con.rollback()
        resultado, motivo = "RECUSADO", f"erro interno: {type(e).__name__}"
    finally:
        if resultado == "RECUSADO":
            try:
                _gravar(auditoria, admin_id, alvo_id, anterior, novo_nivel, resultado, motivo)
            except Exception:                             # auditoria indisponivel nao pode derrubar a recusa
                pass
    return resultado, motivo


def _gravar(auditoria, quem, alvo, anterior, novo, resultado, motivo):
    auditoria.insert_one({"quem": quem, "alvo": alvo, "nivel_anterior": anterior, "nivel_novo": novo,
                          "resultado": resultado, "motivo": motivo,
                          "timestamp": datetime.now(timezone.utc)})


def nivel_atual(con, uid):
    cur = con.cursor()
    cur.execute("SELECT nivel_acesso FROM usuarios_aud WHERE id = %s", (uid,))
    return cur.fetchone()[0]


if __name__ == "__main__":
    con = get_mysql("cp2", criar=True)
    aud = get_mongo_db("cp2")["auditoria"]
    aud.delete_many({})
    preparar(con)
    for admin, alvo, nivel in [(1, 2, 4), (2, 3, 5), (1, 1, 9), (1, 99, 3)]:
        r, motivo = alterar_nivel(con, aud, admin, alvo, nivel)
        extra = f"Alvo {alvo}: nível {nivel_atual(con, alvo)}" if alvo != 99 else ""
        print(f"alterar_nivel({admin}, {alvo}, {nivel}) -> {r} {('(' + motivo + ')') if motivo else ''} {extra}")
    print(f"Trilha de auditoria ao final: {aud.count_documents({})} documentos")
    print('db.auditoria.count_documents({"resultado":"RECUSADO"}) ->',
          aud.count_documents({"resultado": "RECUSADO"}))
    con.close()
