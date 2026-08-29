# Proposta de TCC — Projeto Prático Final

## Copiloto de SOC 4.0 para triagem e resposta a incidentes: um estudo comparativo entre SLM local e LLM em nuvem (AWS), com RAG sobre MITRE ATT&CK, agentes com Guardrails e práticas de AgentOps

> **Programa:** Pós-graduação PUC-Rio / ICA — IA Generativa & LLMs (2025.2) — entrega no padrão [ICA-cursos/PoCs](https://github.com/ICA-cursos/PoCs)
> **Autor:** Leonardo Nunes
> **Linha:** SOC 4.0 / Automação de Segurança orientada por IA
> **Nota:** o currículo da pós de Cibersegurança da DSA foi usado como **referência temática**
> para delimitar o problema (SOC 4.0), mas o trabalho é apresentado ao curso da PUC-Rio.

---

## 1. Contexto e motivação

Um **SOC** (Security Operations Center) recebe milhares de alertas por dia de firewalls,
IDS/IPS, EDR e SIEM. A maioria é falso positivo, mas cada alerta exige triagem: entender
o que aconteceu, enriquecer com contexto (reputação de IP, CVE, técnica de ataque) e
priorizar. Esse trabalho manual causa *alert fatigue* — analistas se saturam e alertas
reais passam batido. O estado da arte que a própria pós chama de **SOC 4.0** propõe
resolver isso com **agentes autônomos, pipelines inteligentes e operações orientadas por IA**.

Este trabalho constrói um **copiloto de SOC 4.0** que automatiza a triagem e o
enriquecimento de alertas usando IA Generativa, e — como contribuição central — faz um
**estudo comparativo entre duas arquiteturas de implantação**:

- **On-premises** (SLM via Ollama), priorizando privacidade e soberania de dados;
- **Nuvem** (LLM gerenciado na AWS — Bedrock/SageMaker), priorizando escala e capacidade.

> **O que "on-premises" significa aqui (importante):** *não* é rodar na máquina pessoal do
> analista. É rodar dentro do **perímetro de confiança da empresa** — um servidor com GPU
> no data center ou numa nuvem privada/VPC fechada controlada pela própria organização.
> Os analistas acessam por uma interface, como já fazem com o SIEM. O critério que define
> "on-premises" não é a localização física da máquina, e sim o fato de que **o dado
> sensível (logs, IPs internos, credenciais) nunca é entregue a um modelo de terceiro**.

A pergunta prática que orienta tudo: *quando vale a pena rodar o modelo dentro do próprio
perímetro (privacidade, conformidade, custo) versus na nuvem (qualidade, escala)?* Essa
tensão é exatamente a que um engenheiro de cibersegurança precisa saber resolver.

---

## 1.1 Relevância e impacto — quem ganha com isso

**Para o analista de SOC.** Hoje o analista gasta o turno triando manualmente uma enxurrada
de alertas, dos quais a grande maioria é falso positivo. Isso gera *alert fatigue* e faz
alertas reais se perderem no meio do ruído. O copiloto entrega o alerta já enriquecido e
priorizado ("isto é um SQLi, técnica ATT&CK T1190, prioridade alta, ação recomendada X"),
deslocando o analista de *triador manual* para *tomador de decisão*. Menos esgotamento,
menos alerta crítico perdido.

**Para a empresa.** Três ganhos concretos:
- **Custo/capacidade:** analistas de segurança são caros e escassos; ao filtrar o ruído, a
  mesma equipe cobre muito mais volume sem novas contratações.
- **Redução de risco:** cai o tempo de detecção (MTTD) — quanto antes o incidente é visto,
  menor o dano causado pelo atacante.
- **Conformidade/soberania (LGPD):** na arquitetura on-premises, logs sensíveis não saem do
  perímetro da organização — requisito crítico para bancos, saúde, governo e setores regulados.

**A contribuição-síntese (o valor de mercado).** Toda organização que quer adotar IA em
segurança trava na mesma decisão sem dados: *rodar on-premises ou na nuvem?* Este trabalho
entrega uma **tabela de decisão quantitativa** (qualidade × custo × privacidade × disponibilidade
× escala), transformando uma escolha "por achismo" em uma escolha baseada em evidência.
É material diretamente aplicável a uma consultoria ou a uma reunião de arquitetura real.

**Limite honesto (a ser declarado no TCC).** O copiloto **acelera e organiza** a triagem —
não substitui o analista nem detecta ameaças inéditas por si só. Assumir isso explicitamente
demonstra maturidade e antecipa a crítica da banca.

---

## 1.2 Trabalhos relacionados e estado da arte

O conceito de *AI SOC Analyst* — um agente que triage, enriquece, investiga e entrega um
veredito ao humano — é hoje uma categoria consolidada de mercado (2026), não uma ideia
inédita. É fundamental posicionar este trabalho **frente ao que já existe** e deixar claro
qual lacuna ele preenche.

### Soluções comerciais (proprietárias)

| Produto | Abordagem |
|---------|-----------|
| **Microsoft Security Copilot** (no Defender) | Copiloto nativo do ecossistema Microsoft; entrou no pacote M365 E5 em jan/2026, tornando-se o mais difundido |
| **CrowdStrike Charlotte AI** | Agente nativo da plataforma Falcon |
| **SentinelOne Purple AI** | Agente nativo do ecossistema SentinelOne |
| **Palo Alto Cortex (AgentiX)** | Agentes sobre o Cortex XSIAM |
| **Dropzone AI, Radiant Security, Qevlar AI, Prophet Security** | *Startups* focadas especificamente em triagem autônoma, escopo mais estreito e menor custo |
| **D3 Morpheus, Torq, Conifers** | Motores de investigação / plataformas multiagente componíveis |

O mercado inclusive já classifica o grau de autonomia em níveis (ex.: *nível 3* = copiloto
assistido, 40–60% de automação; *nível 4* = agêntico com humano no loop, 70–85%).

### Soluções open-source / self-hosted (mais próximas deste trabalho)

| Projeto | Características |
|---------|----------------|
| **AiSOC** (MIT) | SOC open-source self-hostable; triagem por agente, investigação MITRE ATT&CK, *Investigation Ledger* auditável |
| **AI_SOC** (zhadyz) | IDS treinado + LLM local + RAG + Wazuh + TheHive; usa o modelo Foundation-Sec-8B |
| **Triagem com Ollama + Llama 3.1 8B** | Artigos/PoCs demonstrando triagem 100% on-premises para compliance (GDPR/HIPAA) |

### Prática de mercado: LLMs para análise de logs

Além dos produtos de SOC, a própria indústria de observabilidade já tratou a análise de
logs com LLMs como prática estabelecida. A Splunk — referência de mercado em gestão de
logs — publicou um guia técnico ([*LLMs for Log File Analysis*, dez/2025](https://www.splunk.com/en_us/blog/learn/log-file-analysis-llms.html))
que consolida dois pontos adotados por este trabalho:

1. **Arquitetura híbrida / uso seletivo do LLM:** não se envia todo log ao modelo; o
   pipeline tradicional (coleta, filtragem, agregação) continua fazendo o trabalho barato
   em volume, e o LLM é acionado **seletivamente** para os eventos que exigem raciocínio
   contextual. É exatamente o desenho deste copiloto (o LLM triage *alertas*, não o fluxo
   bruto) — e é o que torna a comparação de custos local × nuvem realista.
2. **Limitações documentadas pela indústria**, que este TCC trata explicitamente como
   requisitos de avaliação: janela de contexto (exige *chunking* de logs longos), fraca
   correlação temporal entre eventos (mitigada aqui pelo enriquecimento estruturado
   *antes* do LLM), custo proibitivo em volume (mitigado pelo uso seletivo), saídas
   não-determinísticas e alucinação (mitigadas por temperatura baixa, saída estruturada
   validada por schema e humano no loop — as mesmas recomendações do guia).

### A lacuna que este TCC preenche

Todos os produtos comerciais **vendem** a solução, mas **não publicam evidência
independente e reproduzível** do custo-benefício — em especial, ninguém divulga uma
comparação medida entre rodar o modelo **on-premises** (SLM) versus **na nuvem** (LLM
gerenciado). Os projetos open-source provam que a arquitetura on-premises é viável, mas
tampouco fazem essa **avaliação comparativa quantitativa**.

> **Contribuição deste trabalho:** não é *construir mais um* copiloto de SOC (isso já
> existe), e sim **medir de forma independente e reproduzível o trade-off on-premises ×
> nuvem** (qualidade × custo × privacidade × disponibilidade × escala), usando um copiloto
> de referência e datasets públicos, entregando um **guia de decisão baseado em evidência**
> — algo que os fornecedores, por interesse comercial, não publicam.

Consequência prática: os projetos open-source acima (AiSOC, AI_SOC) podem ser usados como
**base de implementação e/ou ponto de comparação**, poupando esforço de construção e
concentrando a energia do TCC na avaliação rigorosa — que é onde está o mérito acadêmico.

---

## 1.3 Escopo e delimitação

O copiloto atua **depois da detecção**: ele não gera alertas nem monitora infraestrutura,
ele **analisa e triage eventos de segurança que outras ferramentas já produziram**.

```
Rede / servidor / app  →  ferramenta de detecção  →  ALERTA/LOG  →  [COPILOTO]  →  veredito
 (o que acontece)         (IDS, firewall, WAF,        (o INPUT       (triage,
                           EDR, SIEM, log web)         do trabalho)   prioriza, explica)
```

### Dentro do escopo

- **Entrada:** alertas e logs de segurança **já existentes**, a partir de **datasets
  públicos rotulados** (reproduzível, sem necessidade de rede real).
- **Tipos de evento cobertos** (alinhados às disciplinas da pós):
  - alertas de **intrusão de rede** (CIC-IDS2017 / UNSW-NB15) — Disc. 1;
  - **ataques a aplicação web**: SQL injection, acessos suspeitos — Disc. 1;
  - **phishing** (e-mails / URLs) — Disc. 1;
  - **logs de servidor web** para geração de relatório — Disc. 1.
- **Processamento:** triagem, enriquecimento, priorização, justificativa e relatório.
- **Comparação:** implantação on-premises (SLM) × nuvem (AWS).
- **O pipeline do próprio copiloto** (ingestão → enriquecimento → RAG → classificação →
  relatório) é construído e observado via **AgentOps** — Disc. 6.

### Fora do escopo (explicitamente)

- **Monitoramento de infraestrutura em tempo real** (tipo Zabbix/Datadog) — é observabilidade,
  não triagem de segurança. Ingestão ao vivo (Wazuh/Suricata) fica como **trabalho futuro**.
- **Monitoramento de pipelines de dados, ETL ou jobs** de outras aplicações — é engenharia
  de dados/SRE; segurança de pipeline seria um tema próprio.
- **Detecção primária** (ser o IDS/EDR) — o trabalho consome a saída dessas ferramentas,
  não as substitui.
- **Resposta ativa automática** (bloquear IP, isolar host) sem humano — mantém-se
  *human-in-the-loop*; o copiloto recomenda, o analista decide.

> **Por que delimitar assim:** a pergunta de pesquisa é sobre **qualidade da análise** e
> **trade-off on-premises × nuvem** — não sobre velocidade de ingestão. Um dataset estático
> serve melhor a isso, pois garante resultado **reproduzível**. Tempo real adicionaria
> complexidade de engenharia sem contribuir para a pergunta científica.

---

## 2. Problema de pesquisa

> **Um copiloto de SOC baseado em IA Generativa (RAG + agentes com Guardrails) consegue
> triar e priorizar alertas de segurança com qualidade utilizável, e qual arquitetura de
> implantação — SLM local ou LLM em nuvem — oferece o melhor equilíbrio entre qualidade,
> custo, privacidade e disponibilidade para cada tipo de cenário?**

Perguntas específicas:
1. Qual o *trade-off* de qualidade entre o SLM local e o LLM de nuvem na triagem?
2. RAG sobre MITRE ATT&CK/CVE melhora a precisão da classificação e a qualidade da
   justificativa frente ao modelo sem contexto?
3. **Fine-tuning** de um LLM para detecção de anomalias melhora a triagem (conexão direta
   com o Projeto 8 da Disciplina 1)?
4. **Guardrails** e uma arquitetura **multiagente** reduzem erros perigosos e alucinações
   na investigação de alertas (conexão com a Disciplina 2)?
5. Como garantir **alta disponibilidade e proteção dos dados** (logs sensíveis, LGPD) do
   próprio copiloto (Disciplina 5)?

---

## 3. Objetivos

**Geral:** projetar, implementar e avaliar um copiloto de SOC 4.0 que recebe um alerta
bruto, o enriquece via agentes, recupera contexto de ameaças via RAG e devolve uma
classificação de prioridade com justificativa rastreável — comparando implantação local
e em nuvem.

**Específicos:**
1. Construir uma base de conhecimento vetorial (MITRE ATT&CK + CVEs) para RAG.
2. Implementar o pipeline de triagem: alerta → enriquecimento → RAG → classificação.
3. Implementar uma arquitetura **multiagente com Guardrails** para investigação.
4. Aplicar **fine-tuning** para melhorar a detecção de anomalias/priorização.
5. Implantar as duas arquiteturas (local via Ollama; nuvem via AWS Bedrock/SageMaker).
6. Aplicar **AgentOps**: monitoramento, versionamento de prompts, avaliação contínua.
7. Garantir **alta disponibilidade e proteção de dados** do próprio sistema.
8. Avaliar rigorosamente qualidade, custo, privacidade e disponibilidade.

---

## 4. Mapeamento disciplina → módulo

### 4.1 Disciplinas do curso (PUC-Rio / ICA)

O trabalho exercita diretamente 5 das 6 disciplinas do curso (e a sexta opcionalmente):

| Disciplina PUC | Como aparece no TCC |
|---|---|
| **01-TDP** (Transformando Dados) | Ingestão e normalização de logs/alertas (CIC-IDS2017, UNSW-NB15), parsing de payloads, feature engineering, construção do golden set |
| **02-DPIA** (Programação p/ IA) | Baselines de ML clássico da triagem (Random Forest/XGBoost) — essencial ao ablation "clássico × LLM" — e avaliação com métricas |
| **03-PAI** (Imagens) | *Opcional:* detecção de phishing por similaridade visual (screenshot da página suspeita × página legítima, embeddings de imagem) |
| **04-NLP** (Linguagem Natural) | Classificação de e-mails de phishing, processamento do texto de logs/alertas, embeddings para o índice vetorial do RAG |
| **05-DGL** (Deep Generative) | LLMs como modelos generativos: geração de relatórios de incidente, fine-tuning do SLM, dados sintéticos de alertas |
| **06-PLNA** (NLP Avançado) | Núcleo do trabalho: transformers, RAG sobre MITRE ATT&CK, agentes com guardrails, fine-tuning, avaliação (RAGAS) |

### 4.2 Referência temática externa (currículo DSA de Cibersegurança)

O tema foi delimitado usando como referência o currículo de uma pós de mercado em
cibersegurança (DSA), o que garante que o problema atacado é o que a indústria de
segurança considera atual (SOC 4.0). O mapeamento abaixo mostra essa aderência temática:

| Disciplina (DSA — referência) | O que ela ensina | Como aparece no TCC |
|-----------|------------------|----------------------|
| **1. IA para Segurança Cibernética** (84h) | ML/DL/LLM para phishing, intrusão, logs, SQLi, **fine-tuning de LLM p/ anomalia**, **agentes para teste de vulnerabilidade** | Núcleo de detecção: classificação de alertas (phishing, intrusão, SQLi) + fine-tuning para priorização de anomalias |
| **2. Auditoria e Detecção de Fraudes com IA Gen** (64h) | **Agentic RAG**, **multiagentes com Guardrails**, monitoramento contínuo, relatórios automatizados | Arquitetura multiagente de investigação + Guardrails + geração de relatório de incidente |
| **3. Arquiteto de Cloud com AWS** (120h) | S3, RDS, VPC, IAM, CloudWatch, SageMaker, Lambda, API Gateway, IaC, **Bedrock Agents + Guardrails** | Braço "nuvem" do estudo comparativo: deploy do copiloto na AWS (Bedrock/SageMaker/Lambda), monitorado por CloudWatch |
| **4. Cybersecurity de Ataque e Defesa** (96h) | Técnicas ofensivas e defensivas (TTPs) | Geração de cenários de ataque realistas para validar o copiloto + mapeamento das respostas a TTPs/ATT&CK |
| **5. Alta Disponibilidade e Segurança de Dados** (72h) | Resiliência, proteção de dados | Arquitetura resiliente do copiloto + proteção dos logs sensíveis (cifragem, LGPD, retenção) |
| **6. Automação com IA e AgentOps** (84h) | **SOC 4.0**, agentes autônomos, pipelines, operações orientadas por IA | Camada de orquestração/AgentOps: pipeline de triagem, observabilidade e avaliação contínua dos agentes |

> Ou seja: o tema tem dupla ancoragem — exercita as disciplinas de IA do curso da PUC
> (4.1) e cobre o que o mercado de segurança define como estado da prática (4.2).

---

## 5. Fluxo do sistema

```
Alerta bruto (ex.: "IDS: possível SQLi de 203.0.113.10 em /login, payload ' OR 1=1--")
        │
        ▼
[1] AGENTES DE ENRIQUECIMENTO (multiagente + Guardrails)
     • reputação do IP (feed local/offline)  • decodifica/normaliza o payload
     • correlaciona eventos recentes          • Guardrails barram ações inseguras
        │
        ▼
[2] RAG sobre MITRE ATT&CK + CVEs
     • recupera técnica (ex.: T1190 Exploit Public-Facing App) + CVEs relacionados
        │
        ▼
[3] MODELO CLASSIFICA + JUSTIFICA  (SLM local  |  LLM nuvem — os dois braços)
     • prioridade {falso positivo | baixa | média | alta}
     • justificativa citando técnica ATT&CK    • ação recomendada
        │
        ▼
Saída estruturada (JSON) → analista + relatório de incidente + log auditável (AgentOps)
```

---

## 6. Arquitetura técnica (dois braços do estudo)

| Camada | Braço ON-PREMISES | Braço NUVEM (AWS) |
|--------|-------------|-------------------|
| Modelo | Ollama + SLM (Llama 3.2 3B / Qwen3 4B / Llama 3.1 8B) | Amazon Bedrock (Claude/Llama) ou SageMaker endpoint |
| Agentes/Guardrails | LangChain/LlamaIndex + validação Pydantic | Amazon Bedrock Agents + Bedrock Guardrails |
| RAG | Qdrant/ChromaDB + embeddings locais | Bedrock Knowledge Bases / OpenSearch |
| Dados/logs | SQLite + arquivos (SIEM-lite) | RDS + S3, VPC privada, IAM |
| Observabilidade | logs locais + scripts | CloudWatch + AWS Budgets |
| Deploy | servidor on-premises c/ GPU ou VPC privada (container) | Lambda + API Gateway + IaC |

Conexão direta: o braço nuvem é literalmente o conteúdo prático da Disciplina 3.

---

## 7. Datasets e fontes (públicos)

| Uso | Fonte |
|-----|-------|
| Intrusão / alertas rotulados | **CIC-IDS2017**, **NSL-KDD**, **UNSW-NB15** |
| Phishing | **PhishTank**, base Nazario |
| SQL Injection | payloads públicos / logs sintéticos de app web |
| Técnicas de ataque | **MITRE ATT&CK** (Enterprise, STIX 2.1) |
| Vulnerabilidades | **NVD / CVE** (feed JSON) |
| Golden set de triagem | subconjunto rotulado por prioridade (construído no TCC) |

---

## 8. Plano de avaliação (métricas)

**Qualidade da triagem:** precisão, recall, F1 por classe de prioridade + matriz de
confusão (o erro crítico é classificar "alta" como "falso positivo").

**Qualidade do RAG:** *faithfulness* e *context recall* (RAGAS).

**Confiabilidade dos agentes/Guardrails:** taxa de execução correta da ferramenta;
taxa de bloqueios corretos pelo Guardrail; taxa de alucinação.

**Tabela-chave do TCC — Local vs. Nuvem:**

| Dimensão | SLM local | LLM nuvem (AWS) |
|----------|-----------|-----------------|
| F1 na triagem | a medir | a medir |
| Custo (R$/1000 alertas) | ~0 (energia/hardware) | a medir |
| Latência por alerta | a medir | a medir |
| Privacidade / vazamento | dado não sai do perímetro | dado enviado a terceiro |
| Disponibilidade offline | funciona | depende de rede |
| Escala | limitada por hardware | elástica |

**Experimentos (ablation):**
1. Modelo sozinho vs. modelo + RAG.
2. Sem fine-tuning vs. com fine-tuning.
3. Agente único vs. multiagente com Guardrails.
4. SLM local vs. LLM nuvem (o estudo comparativo central).

---

## 9. Metodologia

1. Revisão de literatura: SOC 4.0, agentes LLM, RAG, detecção de intrusão, MITRE ATT&CK,
   e **riscos de segurança de LLMs** (OWASP LLM Top 10 — ex.: prompt injection via alerta
   malicioso, que conecta com a Disciplina 4). Incluir também **fontes de prática de
   mercado** (ex.: guia da Splunk sobre LLMs em análise de logs) para ancorar as decisões
   de arquitetura no que a indústria já validou — separando o que é evidência acadêmica
   do que é prática de fornecedor.
2. Construção da base RAG (ATT&CK + CVEs).
3. Implementação incremental: enriquecimento → RAG → classificação → multiagente.
4. Fine-tuning para priorização de anomalias.
5. Implantação dos dois braços (local e AWS).
6. Construção do golden set + experimentos de ablation.
7. Estudo de caso end-to-end + discussão de ética, LGPD e limitações.

---

## 10. Cronograma (6 meses)

| Mês | Entrega |
|-----|---------|
| 1 | Revisão de literatura + datasets + base RAG indexada |
| 2 | Pipeline base (RAG + classificação) com SLM local |
| 3 | Multiagente + Guardrails + enriquecimento + SIEM-lite |
| 4 | Fine-tuning + golden set + primeiros experimentos |
| 5 | Deploy do braço AWS (Bedrock/SageMaker) + comparação local×nuvem |
| 6 | Estudo de caso end-to-end + AgentOps + redação final + defesa |

---

## 11. Entregáveis

- Monografia / relatório do Projeto Prático Final.
- Repositório GitHub documentado, no padrão de entrega ICA-cursos/PoCs (ver seção 14).
- Golden set rotulado + notebooks de avaliação reproduzíveis.
- Demo: "triar este alerta" → JSON com prioridade + justificativa ATT&CK + relatório.
- Tabela comparativa local × nuvem (a contribuição-síntese).

---

## 12. Riscos e mitigação

| Risco | Mitigação |
|-------|-----------|
| Modelo erra tool calling / ação perigosa | Guardrails, allowlist, saída Pydantic validada, humano no loop |
| Prompt injection via alerta malicioso | separação instrução×dado, sanitização, testes adversariais (Disc. 4) |
| Hardware limitado (VRAM) no braço local | SLM 3B–4B quantizado; degradar para CPU |
| Custo AWS no braço nuvem | AWS Budgets + free tier + desligar recursos; medir só o necessário |
| Escopo grande | MVP = RAG + classificação local; extensões = multiagente, fine-tuning, braço AWS |
| Logs/alertas excedem a janela de contexto | *Chunking* + sumarização hierárquica; enriquecimento estruturado antes do LLM (Splunk, 2025) |
| Saída não-determinística entre execuções | Temperatura 0, saída JSON validada por schema, N execuções por item no golden set (reporta média ± desvio) |
| LLM correlaciona mal eventos no tempo | Correlação temporal feita por código no enriquecimento (janelas de tempo, contagens); o LLM recebe o contexto já correlacionado |

---

## 13. Contribuições esperadas

1. Um **copiloto de SOC 4.0** funcional e de código aberto.
2. Evidência empírica do **trade-off local × nuvem** para operações de segurança.
3. Uma **metodologia de avaliação** (golden set + ablation) reaproveitável.
4. Portfólio demonstrável no GitHub, alinhado ao objetivo de empregabilidade da pós.

---

## 14. Formato de entrega (padrão ICA-cursos/PoCs)

A entrega segue o padrão do curso ([ICA-cursos/PoCs](https://github.com/ICA-cursos/PoCs),
template `templates/readme_bi-master.md`) — o tema é livre, e há PoCs aprovadas de
segurança (ex.: detecção de força bruta SSH via anomalias em Netflow) e de saúde, o que
confirma a adequação temática deste trabalho.

**Checklist da entrega:**
- [ ] Repositório GitHub com o código (este projeto) documentado e reproduzível
- [ ] README no template ICA: título; aluno e orientador(a) com links de GitHub;
      declaração formal do curso; link para o código; link para a monografia;
      trabalhos relacionados; **Resumo (PT)** e Abstract (EN, opcional); matrícula
- [ ] Remover todos os comentários HTML do template antes da versão final
- [ ] Monografia como documento separado, linkada no README
- [ ] Definir orientador(a) e alinhar escopo com ele(a)
