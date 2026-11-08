"""Exercicio 10.2 - Explorador da API do GitHub (menu).

Opcoes: (1) buscar usuario  (2) listar repositorios (paginado)
        (3) detalhar repositorio  (4) salvar resultados em JSON  (0) sair
Token opcional (limite de 5000 req/h em vez de 60): variavel GITHUB_TOKEN.
"""
import json
import os
import re
from pathlib import Path

import requests

API = "https://api.github.com"
PADRAO_NOME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$")
PASTA_SAIDA = Path(__file__).resolve().parents[1] / "saida"


class ErroGitHub(Exception):
    pass


def _headers():
    h = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        h["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    return h


def _validar_nome(nome):
    if not PADRAO_NOME.match(nome or ""):
        raise ErroGitHub(f"Nome inválido: {nome!r}")
    return nome


def requisitar(caminho, params=None, get=requests.get):
    """GET com tratamento de timeout, conexao, 404 e limite de requisicoes (403/429)."""
    try:
        r = get(f"{API}{caminho}", params=params, headers=_headers(), timeout=15)
    except requests.exceptions.Timeout:
        raise ErroGitHub("Tempo esgotado ao falar com o GitHub") from None
    except requests.exceptions.ConnectionError:
        raise ErroGitHub("Sem conexão com o GitHub") from None
    if r.status_code == 404:
        raise ErroGitHub("Não encontrado (404)")
    if r.status_code in (403, 429):
        reset = r.headers.get("X-RateLimit-Reset", "?")
        raise ErroGitHub(f"Limite de requisições atingido ({r.status_code}); renova em epoch {reset}")
    if r.status_code != 200:
        raise ErroGitHub(f"GitHub respondeu HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError:
        raise ErroGitHub("Resposta inválida do GitHub") from None


def buscar_usuario(usuario, get=requests.get):
    return requisitar(f"/users/{_validar_nome(usuario)}", get=get)


def listar_repos(usuario, limite=None, get=requests.get):
    """Percorre as paginas (100 por vez) ate esvaziar ou atingir `limite`."""
    _validar_nome(usuario)
    repos, pagina = [], 1
    while True:
        lote = requisitar(f"/users/{usuario}/repos",
                          {"per_page": 100, "page": pagina, "sort": "pushed"}, get=get)
        if not lote:
            break
        repos.extend(lote)
        if len(lote) < 100 or (limite and len(repos) >= limite):
            break
        pagina += 1
    repos.sort(key=lambda r: r.get("stargazers_count", 0), reverse=True)
    return repos[:limite] if limite else repos


def detalhar_repo(usuario, repo, get=requests.get):
    return requisitar(f"/repos/{_validar_nome(usuario)}/{_validar_nome(repo)}", get=get)


def salvar_json(usuario, dados, pasta=PASTA_SAIDA):
    pasta = Path(pasta)
    pasta.mkdir(parents=True, exist_ok=True)
    caminho = pasta / f"github_{_validar_nome(usuario)}.json"
    caminho.write_text(json.dumps(dados, ensure_ascii=False, indent=2), encoding="utf-8")
    return caminho


def exibir_perfil(p):
    print(f"=== Perfil: {p['login']} ===")
    print(f"Nome: {p.get('name') or '-'} | Repos públicos: {p['public_repos']} | "
          f"Seguidores: {p['followers']}")


def exibir_repos(repos, n=10):
    print("=== Repositórios (por estrelas) ===")
    for i, r in enumerate(repos[:n], 1):
        print(f"{i}. {r['name']:<20} ★ {r['stargazers_count']:<7} ({r.get('language') or '-'})")


def menu():
    usuario, perfil, repos = None, None, []
    while True:
        print("\n[1] Buscar usuário [2] Listar repositórios [3] Detalhar repositório "
              "[4] Salvar JSON [0] Sair")
        op = input("Opção: ").strip()
        try:
            if op == "1":
                usuario = input("Usuário: ").strip()
                perfil = buscar_usuario(usuario)
                exibir_perfil(perfil)
            elif op == "2":
                usuario = usuario or input("Usuário: ").strip()
                repos = listar_repos(usuario)
                exibir_repos(repos)
            elif op == "3":
                r = detalhar_repo(usuario or input("Usuário: ").strip(), input("Repositório: ").strip())
                print(f"{r['full_name']} — {r.get('description') or 'sem descrição'}\n"
                      f"★ {r['stargazers_count']}  forks {r['forks_count']}  "
                      f"issues {r['open_issues_count']}  linguagem {r.get('language')}")
            elif op == "4":
                if not usuario or not (perfil or repos):
                    print("Busque um usuário/repositórios antes de salvar.")
                else:
                    print(f"Resultados salvos em {salvar_json(usuario, {'perfil': perfil, 'repos': repos})}")
            elif op == "0":
                break
            else:
                print("Opção inválida")
        except ErroGitHub as e:
            print(f"Erro: {e}")


if __name__ == "__main__":
    menu()
