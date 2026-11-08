# SecuraPy — Exercícios do 2º Semestre (Coding for Security)

Resolução dos exercícios de `apostila_2semestre.md` (Aulas 1–4, 6–8 e 10–13) usando o
repositório **securaPy** como base. O que veio do 1º semestre é importado de
`../GS_1Semestre/securaPy` (via [comum.py](comum.py)), não copiado:

| Reaproveitado do SecuraPy | Usado em |
|---|---|
| `logs/auth.log`, `logs/web_access.log` + `coletor.py` | 2.2, 2.3, 13.2 |
| `enriquecimento.eh_ip_privado` | 6.3, 10.3 |
| `integridade.calcular_hash_arquivo` (SHA-256) | 12.3 |

## Preparação

```bash
pip install -r requirements.txt
cp .env.example .env        # defina MYSQL_PASSWORD (e os tokens do CP2/ex10); o .env fica fora do Git
docker compose up -d        # MongoDB (27017) + MySQL (3306)
python -m pytest testes -q  # 94 testes (Aulas + CP1 + CP2)
```

Conexões configuráveis por variável de ambiente: `MONGO_URI`, `MYSQL_HOST`, `MYSQL_PORT`,
`MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DATABASE`. Sem MongoDB/MySQL, os testes usam `mongomock`
e pulam os de MySQL.

## Check Points (`cp1_2semestre.md` e `cp2_cumulativo_2semestre.md`)

- **CP1** (10 exercícios): [checkpoints/cp1/](checkpoints/cp1/) — um arquivo por exercício (7–9 juntos em `ex07_08_09_ml.py`); `python checkpoints/cp1/exNN_*.py`.
- **CP2** (10 exercícios): [checkpoints/cp2/](checkpoints/cp2/); o desafio 10 está em [checkpoints/cp2/ex10/](checkpoints/cp2/ex10/) (`app_vulneravel.py`, `app_seguro.py`, `exploit.py`, [auditoria.md](checkpoints/cp2/ex10/auditoria.md)).
  Prova do ex. 10: `exploit.py` contra a versão vulnerável = 6 de 6 ataques; contra `app_seguro.py` = 0 de 6.
- Não existe `cp3_2semestre.md` no repositório do professor; o **projeto final (GS)** está em [`../securaPy_platform/`](../securaPy_platform/).
- No CP2, `auditoria` (ex. 4) e `previsoes` (ex. 8) gravam no MongoDB; a chave de API do ex. 6 é guardada como SHA-256.

## Exercícios das aulas

| Ex. | Arquivo | Como rodar / observações |
|---|---|---|
| 1.1 | [aula01/ex1_1_vulnerabilidades.sql](aula01/ex1_1_vulnerabilidades.sql) | `docker exec -i mysql-lab mysql -uroot -p"$MYSQL_PASSWORD" seguranca < aula01/ex1_1_vulnerabilidades.sql` |
| 1.2 | [aula01/ex1_2_crud_alertas.sql](aula01/ex1_2_crud_alertas.sql) | idem |
| 1.3 | [aula01/decisoes_cap.md](aula01/decisoes_cap.md) | tabela CP/AP com justificativas |
| 2.1 | [aula02/ex2_1_inventario.py](aula02/ex2_1_inventario.py) | menu; índice único em `ip` |
| 2.2 | [aula02/ex2_2_ingestao_logs.py](aula02/ex2_2_ingestao_logs.py) | 23 eventos do `auth.log`, top IPs por agregação |
| 2.3 | [aula02/ex2_3_consultar.py](aula02/ex2_3_consultar.py) | filtro dinâmico |
| 3.1 | [aula03/ex3_1_usuarios.py](aula03/ex3_1_usuarios.py) | menu; tudo parametrizado; nível 1–5 |
| 3.2 | [aula03/ex3_2_sql_injection.py](aula03/ex3_2_sql_injection.py) | inseguro retorna 3, seguro retorna 0 |
| 3.3 | [aula03/ex3_3_relatorio_alertas.py](aula03/ex3_3_relatorio_alertas.py) | `GROUP BY` por severidade/tipo/IP |
| 4.1–4.3 | [aula04/](aula04/) | phishing (RF), anomalias (Isolation Forest), matriz de confusão |
| 6.1–6.3 | [aula06/](aula06/) | APIs Flask (`create_app()`), `python aula06/ex6_1_api_usuarios.py` |
| 7.1 + 7.2 | [aula07/ex7_incidentes_mongo.py](aula07/ex7_incidentes_mongo.py) | CRUD + paginação/filtros/ordenação (parâmetros documentados no cabeçalho) |
| 7.3 | [aula07/ex7_3_usuarios_mysql.py](aula07/ex7_3_usuarios_mysql.py) | 400/404/409 e 500 sem vazar detalhes |
| 8.1 | [aula08/ex8_1_dashboard_xss.py](aula08/ex8_1_dashboard_xss.py) | payload `<script>` exibido como texto + headers de segurança |
| 8.2 | [aula08/ex8_2_login.py](aula08/ex8_2_login.py) | MySQL parametrizado, hash de senha, 429 após 5 falhas, 401 genérico |
| 8.3 | [aula08/auditoria.md](aula08/auditoria.md) | 5 falhas → OWASP → correção + código corrigido |
| 10.1 | [aula10/ex10_1_nvd.py](aula10/ex10_1_nvd.py) | `python aula10/ex10_1_nvd.py CVE-2021-44228` (API real) |
| 10.2 | [aula10/ex10_2_github.py](aula10/ex10_2_github.py) | menu; JSON salvo em `saida/` |
| 10.3 | [aula10/ex10_3_enriquecedor.py](aula10/ex10_3_enriquecedor.py) | cache + backoff em 429 (falhas não entram no cache) |
| 11.1–11.3 | [aula11/](aula11/) | exigem Docker em execução |
| 12.1–12.3 | [aula12/](aula12/) | pipeline, torneio, `joblib` + SHA-256 |
| 13.1–13.3 | [aula13/](aula13/) | LLM com fallback; doc. da injeção em [aula13/ex13_3_documentacao.md](aula13/ex13_3_documentacao.md) |

## Pontos de atenção

- **Aulas 5, 9 e 14** (Check Points e projeto final): CP1 e CP2 estão em `checkpoints/`, a GS em `../securaPy_platform/`. O `cp3_2semestre.md` não existe no repositório do professor, então não há solução de CP3.
- **2.2:** o `auth.log` tem **11** falhas para `185.220.101.1` (o enunciado diz 10); os 23 eventos e
  os demais valores conferem. Os testes do 1º semestre também esperam 11.
- **12.x:** o dataset é linearmente separável, então RandomForest, SVM e KNN empatam em 1,00 na
  validação cruzada (o enunciado mostra 0,93/0,87/0,80 apenas como exemplo). Empate → vale o primeiro.
- **13.x:** não havia `OPENAI_API_KEY`; tudo rodou com `ClienteMock` (indicado como `llm-mock` na saída).
  O mock reaproveita as regras, então o resultado de 13.2 demonstra o pipeline, **não** a qualidade de um
  LLM real. Com a variável definida, o mesmo código usa `gpt-4o-mini`.
- Nenhuma credencial fica no código: usuário/senha dos bancos vêm de variáveis de ambiente (os padrões
  `definido no .env` são os do `docker-compose.yml` de laboratório).
