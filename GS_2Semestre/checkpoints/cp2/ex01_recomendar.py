"""CP2 - Exercicio 1: assistente de decisao de armazenamento (Aulas 1 e 8).

recomendar(perfil) devolve banco, lado do CAP, justificativa (que NOMEIA o erro
inaceitavel do cenario) e o risco OWASP 2025 criado por uma escolha errada.
A decisao e uma cascata de regras explicita; cada ramo carrega o seu texto.
"""

CHAVES = ("schema_fixo", "precisa_acid", "escala_horizontal",
          "tolera_atraso_de_consistencia", "dado_sensivel")


def _validar(perfil):
    faltando = [c for c in CHAVES if c not in perfil]
    if faltando:
        raise ValueError(f"perfil incompleto, faltam: {', '.join(faltando)}")
    if any(not isinstance(perfil[c], bool) for c in CHAVES):
        raise ValueError("todas as chaves do perfil devem ser booleanas")


def recomendar(perfil):
    _validar(perfil)
    sensivel = perfil["dado_sensivel"]

    if perfil["precisa_acid"]:
        # transacao atomica entre varias linhas: so um relacional entrega isso de forma nativa
        banco, cap = "MySQL", "CP"
        if sensivel:
            erro = "autenticar ou autorizar errado (aceitar uma credencial revogada ou negar a legítima)"
            risco = "A07 – Authentication Failures"
        else:
            erro = "vender a mesma licença duas vezes (leitura desatualizada + escrita concorrente)"
            risco = "A06 – Insecure Design"
        justificativa = (f"Precisa de ACID e consistência forte; o erro inaceitável é {erro}. "
                         "Melhor ficar indisponível durante uma partição do que responder errado.")
    elif not perfil["tolera_atraso_de_consistencia"]:
        # sem ACID multi-linha, mas sem tolerar divergencia: Mongo com write concern "majority"
        banco, cap = "MongoDB", "CP"
        erro = "dois nós exibirem históricos diferentes: um registro divergente ou perdido não vale como prova"
        justificativa = (f"Não exige transação entre tabelas, mas o erro inaceitável é {erro}. "
                         "Usar write concern 'majority' e aceitar recusar a escrita numa partição.")
        risco = "A08 – Software or Data Integrity Failures"
    else:
        banco, cap = "MongoDB", "AP"
        if sensivel:
            erro = "aceitar uma sessão já revogada por ler uma réplica atrasada"
            risco = "A07 – Authentication Failures"
            extra = "Mitigar com TTL curto e lista de revogação consultada em cada uso."
        else:
            erro = "parar de aceitar eventos durante um ataque (perder 1 s de log é tolerável; ficar cego não)"
            risco = "A09 – Security Logging & Alerting Failures"
            extra = "Escalar horizontalmente e aceitar consistência eventual."
        justificativa = (f"Tolera atraso de consistência; o erro inaceitável é {erro}. "
                         f"Prioriza disponibilidade. {extra}")

    if not perfil["schema_fixo"] and banco == "MySQL":
        justificativa += " Atenção: schema variável pede colunas JSON ou revisão do modelo."
    return {"banco": banco, "cap": cap, "justificativa": justificativa, "risco_owasp": risco}


PERFIS = {
    "credenciais_do_SOC": {"schema_fixo": True, "precisa_acid": True, "escala_horizontal": False,
                           "tolera_atraso_de_consistencia": False, "dado_sensivel": True},
    "telemetria_de_sensores": {"schema_fixo": False, "precisa_acid": False, "escala_horizontal": True,
                               "tolera_atraso_de_consistencia": True, "dado_sensivel": False},
    "trilha_de_auditoria": {"schema_fixo": False, "precisa_acid": False, "escala_horizontal": True,
                            "tolera_atraso_de_consistencia": False, "dado_sensivel": True},
    "carrinho_de_licencas": {"schema_fixo": True, "precisa_acid": True, "escala_horizontal": False,
                             "tolera_atraso_de_consistencia": False, "dado_sensivel": False},
    "cache_de_sessoes": {"schema_fixo": True, "precisa_acid": False, "escala_horizontal": True,
                         "tolera_atraso_de_consistencia": True, "dado_sensivel": True},
}

if __name__ == "__main__":
    for nome, perfil in PERFIS.items():
        r = recomendar(perfil)
        print(f"{nome:<24} -> {r['banco']:<8}| {r['cap']} | {r['risco_owasp'][:3]}")
        print(f"    {r['justificativa']}")
