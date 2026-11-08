"""CP2 - Exercicio 2: migracao relacional (MySQL) -> documentos aninhados (MongoDB)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from comum import get_mongo_db, get_mysql  # noqa: E402

ATIVOS = [(1, "SRV-WEB01", "192.168.1.10", "alta"), (2, "PC-RH03", "192.168.1.45", "baixa")]
ALERTAS = [(1, 1, "BRUTE_FORCE", "critica"), (2, 1, "PORT_SCAN", "alta"), (3, 2, "XSS", "media")]


def criar_e_popular(con):
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS alertas_mig")
    cur.execute("DROP TABLE IF EXISTS ativos_mig")
    cur.execute("""CREATE TABLE ativos_mig (
        id INT PRIMARY KEY, nome VARCHAR(100) NOT NULL, ip VARCHAR(45) NOT NULL UNIQUE,
        criticidade ENUM('baixa','media','alta') NOT NULL)""")
    cur.execute("""CREATE TABLE alertas_mig (
        id INT PRIMARY KEY, ativo_id INT NOT NULL, tipo VARCHAR(50), severidade VARCHAR(20),
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (ativo_id) REFERENCES ativos_mig(id))""")
    cur.executemany("INSERT INTO ativos_mig VALUES (%s, %s, %s, %s)", ATIVOS)
    cur.executemany("INSERT INTO alertas_mig (id, ativo_id, tipo, severidade) VALUES (%s, %s, %s, %s)", ALERTAS)
    con.commit()


def ler_com_join(con, min_id=0):
    """JOIN parametrizado (o filtro por id e passado como parametro, nunca concatenado)."""
    cur = con.cursor(dictionary=True)
    cur.execute("""SELECT a.id, a.tipo, a.severidade, a.criado_em,
                          v.nome, v.ip, v.criticidade
                   FROM alertas_mig a JOIN ativos_mig v ON v.id = a.ativo_id
                   WHERE a.id > %s ORDER BY a.id""", (min_id,))
    return cur.fetchall()


def montar_documentos(linhas):
    return [{"alerta_id": l["id"], "tipo": l["tipo"], "severidade": l["severidade"],
             "criado_em": l["criado_em"],
             "ativo": {"nome": l["nome"], "ip": l["ip"], "criticidade": l["criticidade"]}}
            for l in linhas]


def migrar(con, col):
    col.delete_many({})
    docs = montar_documentos(ler_com_join(con))
    if docs:
        col.insert_many(docs)
    return len(docs)


def verificar(con, col):
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM alertas_mig")
    n_sql, n_mongo = cur.fetchone()[0], col.count_documents({})
    return n_sql, n_mongo, n_sql == n_mongo


if __name__ == "__main__":
    con = get_mysql("cp2", criar=True)
    col = get_mongo_db("cp2")["alertas"]
    criar_e_popular(con)
    migrar(con, col)
    n_sql, n_mongo, ok = verificar(con, col)
    print(f"MySQL: {n_sql} alertas | MongoDB: {n_mongo} documentos -> "
          f"{'MIGRAÇÃO ÍNTEGRA' if ok else 'MIGRAÇÃO COM PERDA!'}")
    print('Consulta sem JOIN: db.alertas.find({"ativo.criticidade":"alta"}) ->',
          col.count_documents({"ativo.criticidade": "alta"}), "documentos")
    # Comentário: ganha-se leitura sem JOIN (o alerta já carrega os dados do ativo);
    # perde-se normalização: renomear o ativo exige update_many em todos os seus alertas.
    con.close()
