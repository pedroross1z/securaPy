"""
Modulo 2 - Motor de Regras
Responsavel por carregar regras de deteccao de um arquivo JSON,
avaliar cada evento contra as regras ativas e gerar alertas
quando uma regra eh violada.

Formato de um alerta gerado:
{
    "timestamp": "2025-02-20 08:15:01",
    "regra_id": "R001",
    "regra_nome": "Login com Usuario Privilegiado",
    "severidade": "MEDIA",
    "ip": "185.220.101.1",
    "descricao": "Tentativa de login com usuario admin"
}

Niveis de severidade (baseados na pontuacao):
    >= 9: CRITICA
    >= 7: ALTA
    >= 5: MEDIA
    >= 3: BAIXA
     < 3: INFO
"""

import json


def _extrair_kv(detalhes):
    """Extrai pares chave=valor do campo 'detalhes' do evento."""
    pares = {}
    if not isinstance(detalhes, str):
        return pares
    for token in detalhes.split():
        if "=" in token:
            chave, _, valor = token.partition("=")
            if chave:
                pares[chave] = valor
    return pares


def carregar_regras(caminho_config):
    """Le o arquivo regras.json e retorna a lista de regras ativas."""
    try:
        with open(caminho_config, "r", encoding="utf-8") as f:
            dados = json.load(f)
    except FileNotFoundError:
        print(f"[ERRO] Arquivo de regras nao encontrado: {caminho_config}")
        return []
    except json.JSONDecodeError as e:
        print(f"[ERRO] JSON invalido em {caminho_config}: {e}")
        return []
    except OSError as e:
        print(f"[ERRO] Erro de I/O ao ler {caminho_config}: {e}")
        return []

    regras = dados.get("regras", []) if isinstance(dados, dict) else []
    return [r for r in regras if isinstance(r, dict) and r.get("ativa", False)]


def classificar_severidade(pontuacao):
    """Converte uma pontuacao numerica em nivel de severidade."""
    if pontuacao >= 9:
        return "CRITICA"
    if pontuacao >= 7:
        return "ALTA"
    if pontuacao >= 5:
        return "MEDIA"
    if pontuacao >= 3:
        return "BAIXA"
    return "INFO"


def _montar_alerta(regra, evento, descricao):
    """Monta o dicionario de alerta no formato padronizado."""
    return {
        "timestamp": evento.get("timestamp", ""),
        "regra_id": regra.get("id", ""),
        "regra_nome": regra.get("nome", ""),
        "severidade": classificar_severidade(regra.get("severidade_base", 0)),
        "ip": evento.get("ip", ""),
        "descricao": descricao,
    }


def avaliar_regra(regra, evento):
    """Avalia se um evento viola uma regra especifica."""
    if regra.get("fonte") != evento.get("fonte"):
        return None

    condicao = regra.get("condicao")
    kv = _extrair_kv(evento.get("detalhes", ""))

    if condicao == "usuario_privilegiado":
        usuario = kv.get("usuario")
        if usuario and usuario in regra.get("usuarios_alvo", []):
            return _montar_alerta(
                regra, evento,
                f"Tentativa de login com usuario {usuario}",
            )
        return None

    if condicao == "porta_critica":
        try:
            dport = int(kv.get("dport", ""))
        except (TypeError, ValueError):
            return None
        if dport in regra.get("portas_criticas", []):
            return _montar_alerta(
                regra, evento,
                f"Acesso bloqueado a porta critica {dport}",
            )
        return None

    if condicao == "path_traversal":
        url = kv.get("url", "")
        if url and any(p in url for p in regra.get("padroes", [])):
            return _montar_alerta(
                regra, evento,
                f"Path traversal detectado na URL {url}",
            )
        return None

    if condicao == "xss":
        url = kv.get("url", "")
        if url and any(p in url for p in regra.get("padroes", [])):
            return _montar_alerta(
                regra, evento,
                f"Padrao de XSS detectado na URL {url}",
            )
        return None

    if condicao == "reconhecimento":
        url = kv.get("url", "")
        if url and any(s in url for s in regra.get("urls_suspeitas", [])):
            return _montar_alerta(
                regra, evento,
                f"Acesso a URL de reconhecimento {url}",
            )
        return None

    return None


def aplicar_regras(eventos, regras):
    """Aplica todas as regras a todos os eventos e retorna os alertas gerados."""
    alertas = []
    for evento in eventos:
        for regra in regras:
            alerta = avaliar_regra(regra, evento)
            if alerta is not None:
                alertas.append(alerta)
    return alertas
