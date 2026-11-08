import pytest
from werkzeug.security import generate_password_hash

import ex8_1_dashboard_xss as ex81
import ex8_2_login as ex82

XSS = "<script>alert('xss')</script>"


def test_8_1_payload_xss_vira_texto():
    c = ex81.create_app().test_client()
    r = c.post("/alertas", data={"tipo": "XSS", "severidade": "alta", "descricao": XSS})
    assert r.status_code == 302
    html = c.get("/").get_data(as_text=True)
    assert XSS not in html                                    # nao existe <script> cru na pagina
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in html   # aparece escapado = texto
    assert "<script>" not in html


def test_8_1_escapa_tambem_o_campo_tipo_e_valida_severidade():
    c = ex81.create_app().test_client()
    c.post("/alertas", data={"tipo": "<img src=x onerror=alert(1)>", "severidade": "baixa"})
    assert "<img src=x" not in c.get("/").get_data(as_text=True)
    assert c.post("/alertas", data={"tipo": "t", "severidade": "<b>"}).status_code == 400


def test_8_1_headers_de_seguranca():
    r = ex81.create_app().test_client().get("/")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Content-Security-Policy"] == "default-src 'self'"


# ---------- 8.2 login ----------
HASHES = {"admin": generate_password_hash("Cyber@2024"),
          "analista": generate_password_hash("S3gur4nca!")}


@pytest.fixture()
def relogio():
    t = {"agora": 0.0}
    f = lambda: t["agora"]       # noqa: E731
    f.avancar = lambda s: t.update(agora=t["agora"] + s)
    return f


@pytest.fixture()
def c(relogio):
    return ex82.create_app(buscar_hash=HASHES.get, relogio=relogio).test_client()


def test_8_2_enunciado(c):
    r = c.post("/login", json={"usuario": "admin", "senha": "errada"})
    assert r.status_code == 401 and r.json == {"erro": "Credenciais inválidas"}
    r = c.post("/login", json={"usuario": "admin", "senha": "Cyber@2024"})
    assert r.status_code == 200 and r.json["mensagem"] == "Login OK"
    assert c.post("/login", json={"usuario": "", "senha": ""}).status_code == 400


def test_8_2_mensagem_identica_para_usuario_inexistente(c):
    a = c.post("/login", json={"usuario": "admin", "senha": "errada"})
    b = c.post("/login", json={"usuario": "fantasma", "senha": "qualquer"})
    assert a.status_code == b.status_code == 401
    assert a.json == b.json


def test_8_2_corpo_invalido(c):
    assert c.post("/login", data="x").status_code == 400
    assert c.post("/login", json={"usuario": "admin"}).status_code == 400
    assert c.post("/login", json={"usuario": 1, "senha": 2}).status_code == 400


def test_8_2_limite_de_tentativas(c, relogio):
    for _ in range(ex82.MAX_FALHAS):
        assert c.post("/login", json={"usuario": "admin", "senha": "x"}).status_code == 401
    # a partir daqui bloqueia ate com a senha CERTA
    assert c.post("/login", json={"usuario": "admin", "senha": "Cyber@2024"}).status_code == 429
    # outro usuario nao e afetado
    assert c.post("/login", json={"usuario": "analista", "senha": "S3gur4nca!"}).status_code == 200
    # passada a janela, libera
    relogio.avancar(ex82.JANELA_SEGUNDOS + 1)
    assert c.post("/login", json={"usuario": "admin", "senha": "Cyber@2024"}).status_code == 200


def test_8_2_contra_mysql_real(mysql_conn):
    ex82.semear(mysql_conn)
    cli = ex82.create_app().test_client()
    assert cli.post("/login", json={"usuario": "admin", "senha": "Cyber@2024"}).status_code == 200
    assert cli.post("/login", json={"usuario": "admin", "senha": "errada"}).status_code == 401
    # SQL injection no campo usuario nao autentica
    assert cli.post("/login", json={"usuario": "' OR '1'='1", "senha": "x"}).status_code == 401
