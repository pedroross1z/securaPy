"""Exercicio 11.1 - Monitor de conteineres (rodando e parados)."""
import docker


def coletar(client=None):
    client = client or docker.from_env()
    linhas = []
    for c in client.containers.list(all=True):
        tags = c.image.tags
        imagem = tags[0] if tags else c.attrs.get("Config", {}).get("Image", "<sem tag>")
        linhas.append({"nome": c.name, "status": c.status, "imagem": imagem})
    return sorted(linhas, key=lambda l: l["nome"])


def formatar(linhas):
    larg = max([len(l["nome"]) for l in linhas] + [4]) + 2
    saida = [f"{'NOME':<{larg}}{'STATUS':<11}IMAGEM"]
    for l in linhas:
        marca = "   <- ⚠️ PARADO" if l["status"] != "running" else ""
        saida.append(f"{l['nome']:<{larg}}{l['status']:<11}{l['imagem']}{marca}")
    rodando = sum(1 for l in linhas if l["status"] == "running")
    saida.append(f"Total: {len(linhas)} | Rodando: {rodando} | Parados: {len(linhas) - rodando}")
    return "\n".join(saida)


if __name__ == "__main__":
    try:
        print(formatar(coletar()))
    except docker.errors.DockerException as e:
        print(f"Erro: não foi possível falar com o Docker ({e})")
