"""Exercicio 3.3 - Relatorio de alertas por severidade, tipo e IP de origem."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from comum import get_mysql  # noqa: E402

ALERTAS = [
    ("BRUTE_FORCE", "10 falhas", "185.220.101.1", "critica"),
    ("BRUTE_FORCE", "5 falhas", "91.240.118.172", "alta"),
    ("BRUTE_FORCE", "8 falhas", "185.220.101.1", "critica"),
    ("BRUTE_FORCE", "7 falhas", "185.220.101.1", "critica"),
    ("PORT_SCAN", "7 portas", "185.220.101.1", "alta"),
    ("PORT_SCAN", "3 portas", "45.33.32.156", "alta"),
    ("PORT_SCAN", "4 portas", "45.33.32.156", "media"),
    ("XSS", "script na URL", "45.33.32.156", "alta"),
    ("XSS", "onerror na URL", "91.240.118.172", "media"),
    ("SQLI", "' OR 1=1", "91.240.118.172", "baixa"),
]

CONSULTAS = {
    "Por severidade": ("SELECT severidade, COUNT(*) AS total FROM alertas "
                       "GROUP BY severidade ORDER BY total DESC, severidade"),
    "Por tipo": ("SELECT tipo, COUNT(*) AS total FROM alertas "
                 "GROUP BY tipo ORDER BY total DESC, tipo"),
    "Top IPs de origem": ("SELECT ip_origem, COUNT(*) AS total FROM alertas "
                          "GROUP BY ip_origem ORDER BY total DESC, ip_origem LIMIT 5"),
}


def preparar(conexao):
    cur = conexao.cursor()
    cur.execute("DROP TABLE IF EXISTS alertas")
    cur.execute("""
        CREATE TABLE alertas (
            id INT AUTO_INCREMENT PRIMARY KEY,
            tipo VARCHAR(50), descricao TEXT, ip_origem VARCHAR(45),
            severidade ENUM('baixa','media','alta','critica'),
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
    cur.executemany("INSERT INTO alertas (tipo, descricao, ip_origem, severidade) "
                    "VALUES (%s, %s, %s, %s)", ALERTAS)
    conexao.commit()


def gerar_relatorio(conexao):
    cur = conexao.cursor()
    resultado = {}
    for titulo, sql in CONSULTAS.items():
        cur.execute(sql)
        resultado[titulo] = cur.fetchall()
    return resultado


if __name__ == "__main__":
    conn = get_mysql()
    try:
        preparar(conn)
        for titulo, linhas in gerar_relatorio(conn).items():
            print(f"=== {titulo} ===")
            if titulo == "Top IPs de origem":
                for ip, n in linhas:
                    print(f"{ip} -> {n} alertas")
            else:
                print(" | ".join(f"{k}: {n}" for k, n in linhas))
    finally:
        conn.close()
