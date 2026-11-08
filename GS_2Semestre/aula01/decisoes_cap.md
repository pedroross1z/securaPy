# Exercício 1.3 — Decisões de arquitetura com o Teorema CAP

Como a tolerância a partição (P) é obrigatória em sistema distribuído, a escolha
real é entre **CP** (prioriza consistência) e **AP** (prioriza disponibilidade).

| # | Cenário | CP/AP | Justificativa |
|---|---------|-------|---------------|
| 1 | Tabela de saldo bancário de clientes | **CP** | Saldo divergente entre nós permite gasto duplo; é melhor recusar a operação durante uma partição do que mostrar um valor errado. |
| 2 | Ingestão de 500 mil eventos de firewall por minuto num SOC | **AP** | O sistema não pode parar de aceitar logs durante um ataque; consistência eventual é aceitável, pois perder/atrasar alguns segundos de telemetria é tolerável. |
| 3 | Cache de tokens de sessão de usuários logados | **AP** (CP para sessões críticas) | Para sessões comuns, disponibilidade e baixa latência importam mais e um token reemitido é barato. Para sessões administrativas/revogação de token, prefira CP: aceitar um token já revogado é falha de segurança. |
| 4 | Registro de quem autorizou cada transferência (auditoria) | **CP** | Trilha de auditoria precisa ser íntegra e idêntica em todos os nós; um registro faltando ou divergente invalida a evidência. Melhor negar a gravação (e a transferência) que auditar errado. |
| 5 | Feed de indicadores de ameaça (IOCs) replicado em 5 regiões | **AP** | Cada região deve continuar consultando o feed mesmo isolada; um IOC chegando alguns segundos depois é aceitável e converge por replicação eventual. |

**Gabarito de referência:** 1=CP, 2=AP, 3=AP (ou CP p/ sessões críticas), 4=CP, 5=AP — confere.

> CAP não é "tudo ou nada": a escolha só é forçada **durante** uma partição. Fora dela, o
> sistema pode oferecer consistência e disponibilidade juntas.
