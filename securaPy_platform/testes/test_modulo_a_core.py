"""Modulo A - nucleo do 1o semestre integrado (cenarios A1-A4) + bonus de correlacao temporal."""
from pathlib import Path

from core import coletor, detector, regras
from settings import carregar_blacklist

RAIZ = Path(__file__).resolve().parents[1]
LOGS = str(RAIZ / "logs")


def test_a1_carrega_os_3_logs_com_fonte_correta():
    eventos = coletor.carregar_todos_os_logs(LOGS)
    assert len(eventos) == 58
    assert {e["fonte"] for e in eventos} == {"auth", "firewall", "web"}
    assert sum(e["fonte"] == "auth" for e in eventos) == 23


def test_a2_brute_force_no_auth_log():
    r = detector.detectar_brute_force(coletor.carregar_todos_os_logs(LOGS))
    assert r["185.220.101.1"]["tentativas"] == 11            # o log tem 11 FAILs (enunciado diz ~10)
    assert r["185.220.101.1"]["severidade"] == "ALTA"          # A2: ALTA
    assert "192.168.1.10" not in r


def test_a3_port_scan_no_firewall_log():
    r = detector.detectar_port_scan(coletor.carregar_todos_os_logs(LOGS))
    assert r["185.220.101.1"]["quantidade"] == 7


def test_a4_blacklist_intersecao():
    eventos = coletor.carregar_todos_os_logs(LOGS)
    achados, contagem = detector.verificar_blacklist(eventos, carregar_blacklist(RAIZ / "config" / "blacklist.txt"))
    assert achados == {"185.220.101.1", "45.33.32.156", "91.240.118.172"}
    assert contagem["185.220.101.1"] > contagem["45.33.32.156"]


def test_regras_geram_alertas_com_severidade():
    eventos = coletor.carregar_todos_os_logs(LOGS)
    alertas = regras.aplicar_regras(eventos, regras.carregar_regras(str(RAIZ / "config" / "regras.json")))
    assert alertas and {a["severidade"] for a in alertas} <= {"CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"}
    assert any(a["regra_id"] == "R003" and a["severidade"] == "CRITICA" for a in alertas)


def test_log_inexistente_ou_malformado_nao_trava(tmp_path):
    assert coletor.carregar_todos_os_logs(str(tmp_path / "nao_existe")) == []
    (tmp_path / "auth.log").write_text("lixo\n\n2025-02-20 08:15:01 FAIL usuario=a ip=1.2.3.4\n"
                                       "2025-02-20 FAIL\n", encoding="utf-8")
    assert len(coletor.carregar_todos_os_logs(str(tmp_path))) == 1


def test_bonus_correlacao_temporal():
    eventos = coletor.carregar_todos_os_logs(LOGS)
    r = detector.detectar_brute_force_temporal(eventos, threshold=5, janela_segundos=60)
    assert r["185.220.101.1"]["tentativas_pico"] >= 5
