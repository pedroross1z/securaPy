"""Testes da Aula 11 sem depender do daemon: usa um cliente Docker falso."""
from types import SimpleNamespace

import ex11_1_monitor as mon
import ex11_3_watchdog as wd


class FakeContainer:
    def __init__(self, nome, status, tags=("img:1",)):
        self.name, self.status = nome, status
        self.image = SimpleNamespace(tags=list(tags))
        self.attrs = {"Config": {"Image": "img:1"}}
        self.reinicios = 0

    def reload(self):
        pass

    def restart(self, timeout=10):
        self.reinicios += 1
        self.status = "running"


class FakeClient:
    def __init__(self, *containers):
        self._c = {c.name: c for c in containers}
        self.containers = SimpleNamespace(list=lambda all=False: list(self._c.values()), get=self._get)

    def _get(self, nome):
        import docker
        if nome not in self._c:
            raise docker.errors.NotFound("nao existe")
        return self._c[nome]


def test_monitor_destaca_parados_e_totaliza():
    cli = FakeClient(FakeContainer("web_lab", "running", ["nginx:latest"]),
                     FakeContainer("cache_lab", "exited", ["redis:latest"]))
    texto = mon.formatar(mon.coletar(cli))
    assert "web_lab" in texto and "nginx:latest" in texto
    linha_cache = next(l for l in texto.splitlines() if l.startswith("cache_lab"))
    assert "PARADO" in linha_cache
    assert texto.splitlines()[-1] == "Total: 2 | Rodando: 1 | Parados: 1"


def test_monitor_imagem_sem_tag():
    cli = FakeClient(FakeContainer("x", "running", tags=[]))
    assert mon.coletar(cli)[0]["imagem"] == "img:1"


def test_watchdog_reinicia_container_parado(capsys):
    web = FakeContainer("web_lab", "exited")
    resultados = wd.watchdog("web_lab", intervalo=0, iteracoes=3, client=FakeClient(web),
                             dormir=lambda s: None)
    assert resultados == ["reiniciado", "ok", "ok"] and web.reinicios == 1
    saida = capsys.readouterr().out
    assert "ALERTA" in saida and "reiniciado com sucesso" in saida and "running — OK" in saida


def test_watchdog_container_inexistente(capsys):
    assert wd.watchdog("fantasma", 0, 1, client=FakeClient(), dormir=lambda s: None) == ["falha"]
    assert "não existe" in capsys.readouterr().out
