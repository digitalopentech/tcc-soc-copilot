# Copiloto de SOC 4.0: triagem de alertas de segurança com RAG sobre MITRE ATT&CK

#### Aluno: [Leonardo Nunes Moreira do Valle](https://github.com/digitalopentech).
#### Orientador: [Leonardo Alfredo Forero Mendoza](https://github.com/leofome8).

---

Trabalho apresentado ao curso [Inteligência Artificial Generativa & Large Language Models](https://ica.ele.puc-rio.br/cursos/ia-generativa-large-language-models/) (2025.2) como pré-requisito para conclusão de curso e obtenção de crédito na disciplina "Projeto LLM".

- [Link para o código](https://github.com/digitalopentech/tcc-soc-copilot).

- Trabalhos relacionados:
    - [AiSOC — Open-source AI Security Operations Center](https://github.com/beenuar/AiSOC).
    - [AI_SOC — SOC aumentado por LLMs com orquestração multiagente](https://github.com/zhadyz/AI_SOC).
    - [LLMs for Log File Analysis — guia técnico da Splunk](https://www.splunk.com/en_us/blog/learn/log-file-analysis-llms.html).
    - [Analisador de Logs de Sistemas Computacionais Utilizando Redes Neurais e Sentence Transformer (PoC ICA/PUC-Rio)](https://github.com/secretaria-ICA/Analisador_de_Logs_de_Sistemas_Computacionais_Utilizando_Redes_Neurais_e_Sentence_Transformer).
    - [Identificação de Ataques de Força Bruta em SSH Utilizando Análise de Anomalias em Fluxos de Rede (PoC ICA/PUC-Rio)](https://github.com/secretaria-ICA/Identificacao_de_Ataques_de_Forca_Bruta_em_SSH_Utilizando_Analise_de_Anomalias_em_Fluxos_de_Rede).

---

### Resumo

Um Centro de Operações de Segurança (SOC) recebe milhares de alertas por dia de firewalls, IDS/IPS, EDR e SIEM. A maioria é falso positivo, mas cada alerta exige triagem — entender o que ocorreu, enriquecer com contexto e priorizar. O resultado é a *alert fatigue*: analistas saturados e alertas reais que passam despercebidos.

Este trabalho projeta, implementa e avalia um **copiloto de triagem de alertas** que recebe um alerta bruto, o enriquece de forma determinística, recupera contexto de ameaças da base **MITRE ATT&CK** por meio de RAG (*Retrieval-Augmented Generation*) e devolve uma classificação de prioridade acompanhada de justificativa rastreável e ação recomendada.

A contribuição central não é construir mais um copiloto — produtos comerciais já existem —, e sim **medir de forma independente e reproduzível** o que cada componente agrega. O sistema foi avaliado em dois conjuntos construídos para o trabalho — um *golden set* de desenvolvimento com 38 alertas e um **benchmark aberto de 240 alertas** cobrindo seis fontes de telemetria (IDS, WAF, EDR, gateway de e-mail, nuvem e identidade), com 20% de casos deliberadamente ambíguos — por meio de experimentos de ablação que comparam três configurações: (i) um classificador determinístico baseado em regras explícitas sobre features extraídas do alerta; (ii) o mesmo pipeline acrescido de recuperação de contexto ATT&CK; e (iii) classificação por um modelo de linguagem (`qwen3:4b`, executado localmente).

Os resultados contrariam a expectativa inicial e constituem a principal contribuição empírica do trabalho. No golden set, o baseline determinístico alcançou **F1-macro de 0,968 com custo de erro zero**, enquanto a configuração com modelo de linguagem obteve **F1-macro de 0,349**, classificando incorretamente como falso positivo 2 dos 12 alertas de prioridade máxima — o modo de falha mais grave em operações de segurança. No benchmark de 240 alertas o quadro se mantém: **F1-macro de 0,707 para o baseline contra 0,333 para o modelo**, que descartou como falso positivo 16 dos 60 alertas de prioridade máxima (o baseline, 8). A recuperação de contexto, por sua vez, demonstrou valor em uma dimensão distinta da priorização: elevou o acerto na identificação da técnica ATT&CK de 0,680 para 0,800 no golden set e de 0,106 para 0,381 no benchmark.

Conclui-se que, para triagem de alertas estruturados, a arquitetura adequada é **híbrida**: o componente determinístico decide a prioridade, enquanto o modelo de linguagem enriquece, contextualiza e redige a justificativa destinada ao analista. A validação externa em UNSW-NB15 e CIC-IDS2017 revelou ainda que os benchmarks públicos de detecção de intrusão não contêm o dado textual que um modelo de linguagem precisa ler — lacuna que motivou a construção do benchmark aberto aqui proposto. Todo o material é reprodutível sem GPU ou serviços de nuvem.

### Abstract

A Security Operations Center (SOC) receives thousands of alerts per day from firewalls, IDS/IPS, EDR and SIEM systems. Most are false positives, yet each alert requires triage — understanding what happened, enriching it with context, and prioritizing it. The outcome is alert fatigue: saturated analysts and genuine alerts slipping through.

This work designs, implements and evaluates an **alert triage copilot** that takes a raw alert, enriches it deterministically, retrieves threat context from the **MITRE ATT&CK** knowledge base through Retrieval-Augmented Generation (RAG), and returns a priority classification with traceable justification and a recommended action.

The core contribution is not building yet another copilot — commercial products already exist — but **independently and reproducibly measuring** what each component adds. The system was evaluated on two datasets built for this work — a 38-alert development golden set and an **open benchmark of 240 alerts** spanning six telemetry sources (IDS, WAF, EDR, e-mail gateway, cloud and identity), 20% of them deliberately ambiguous — through ablation experiments comparing three configurations: (i) a deterministic rule-based classifier over features extracted from the alert; (ii) the same pipeline augmented with ATT&CK context retrieval; and (iii) classification by a language model (`qwen3:4b`, running locally).

The results contradict the initial expectation and constitute the main empirical contribution of this work. On the golden set, the deterministic baseline achieved a **macro-F1 of 0.968 with zero error cost**, whereas the language-model configuration reached a **macro-F1 of 0.349**, misclassifying 2 out of 12 highest-priority alerts as false positives — the most severe failure mode in security operations. On the 240-alert benchmark the picture holds: **macro-F1 of 0.707 for the baseline against 0.333 for the model**, which dismissed 16 of the 60 highest-priority alerts as false positives (the baseline, 8). Context retrieval, in turn, proved valuable along a dimension distinct from prioritization: it raised ATT&CK technique identification accuracy from 0.680 to 0.800 on the golden set and from 0.106 to 0.381 on the benchmark.

We conclude that, for structured alert triage, the appropriate architecture is **hybrid**: the deterministic component decides priority, while the language model enriches, contextualizes and drafts the justification for the analyst. External validation on UNSW-NB15 and CIC-IDS2017 further revealed that public intrusion-detection benchmarks do not carry the textual data a language model needs to read — a gap that motivated the open benchmark proposed here. All material is reproducible without GPU or cloud services.

---

## Como funciona

O copiloto atua **depois da detecção**: recebe o alerta que IDS, WAF, EDR ou SIEM já
produziram e devolve um veredito estruturado. O pipeline tem quatro estágios. Tudo que
precisa ser exato é código determinístico; o modelo de linguagem entra apenas onde o
raciocínio contextual agrega valor.

| Estágio | O que faz | Módulo |
|---|---|---|
| 1. Normalização | Mapeia colunas heterogêneas (CSV/JSON) para o esquema canônico `Alerta`, validado com Pydantic | `ingest.py` |
| 2. Enriquecimento | Classe do IP (privado/público), padrões de ataque por expressão regular, correlação temporal por IP | `enrich.py` |
| 3. Recuperação (RAG) | Busca as técnicas MITRE ATT&CK mais próximas do alerta (TF-IDF, top-3) no catálogo versionado | `retriever.py` |
| 4. Decisão | Regras determinísticas (baseline), modelo de linguagem, ou híbrido: regras decidem a prioridade e o modelo redige a justificativa | `classifier.py` |

A saída é um `Veredito` validado por schema: prioridade (FALSO_POSITIVO · BAIXA · MÉDIA ·
ALTA), confiança, técnica ATT&CK, justificativa e ação recomendada. O campo `modo`
registra qual caminho decidiu — requisito de auditabilidade em operações de segurança.
Detalhes e decisões de projeto em [`docs/ARQUITETURA.md`](./docs/ARQUITETURA.md).

## Exemplo de uso

`make demo` (ou `python -m soc_copilot.cli --demo`) triage um alerta de cada classe de
prioridade, mostrando o que entra e o que sai em cada estágio. Dois dos quatro casos:

```text
[ALT-0001]  rótulo real: ALTA
  1. alerta        : IDS · 2026-03-15 08:00 · 203.0.113.10 → 10.0.1.5:443/TCP · severidade da fonte: high
     descrição     : SQL injection em formulario de login
     payload       : ' OR 1=1--
  2. enriquecimento: ip_origem=publico · padrões=sqli · eventos do mesmo IP em 60 min: 1
  3. recuperação   : T1190 Exploit Public-Facing Application (0.25) · T1598 Phishing for Information (0.17) · T1055 Process Injection (0.14)
  4. veredito      : ALTA ✔  (confiança 0.88 · modo regras)
     técnica       : T1190
     justificativa : fonte classificou como 'high' e o payload confirma o padrao 'sqli' — indicio consistente de ataque em andamento.
     ação          : Escalar imediatamente para o analista de plantão e isolar o host de origem/destino conforme runbook.

[ALT-0030]  rótulo real: FALSO_POSITIVO
  1. alerta        : Scanner · 2026-03-15 10:00 · 10.0.4.10 → 10.0.1.5:443/TCP · severidade da fonte: medium
     descrição     : Scanner de vulnerabilidade agendado
     payload       : Nessus scan janela aprovada
  2. enriquecimento: ip_origem=privado · padrões=nenhum · eventos do mesmo IP em 60 min: 1
  3. recuperação   : T1046 Network Service Discovery (0.38) · T1098 Account Manipulation (0.13) · T1486 Data Encrypted for Impact (0.12)
  4. veredito      : FALSO_POSITIVO ✔  (confiança 0.80 · modo regras)
     técnica       : T1046
     justificativa : atividade compativel com operacao sancionada ou ruido conhecido (scanner agendado, backup, health check, pentest autorizado).
     ação          : Arquivar; opcionalmente ajustar regra de detecção de origem para reduzir ruído.
```

Com `--llm`, o modo híbrido mantém a decisão das regras e pede ao modelo apenas a
redação da justificativa.

## Resultados

### Ablação no golden set (38 alertas)

| Configuração | Acurácia | F1-macro | Custo de erro | Acerto de técnica |
|---|---|---|---|---|
| Baseline (regras determinísticas) | 0,974 | 0,968 | **0** | 0,680 |
| Regras + RAG | 0,974 | 0,968 | **0** | **0,800** |
| LLM (`qwen3:4b`) + RAG | 0,500 | 0,349 | 50 | 0,600 |
| **Híbrido (regras decidem, LLM redige)** | **0,974** | **0,968** | **0** | **0,800** |

### Ablação no benchmark aberto (240 alertas, 6 fontes, 20% ambíguos)

| Configuração | Acurácia | F1-macro | Custo de erro | Acerto de técnica |
|---|---|---|---|---|
| Baseline (regras determinísticas) | 0,733 | 0,707 | 89 | 0,106 |
| Regras + RAG | 0,733 | 0,707 | 89 | 0,381 |
| LLM (`qwen3:4b`) + RAG | 0,438 | 0,333 | 367 | **0,469** |
| **Híbrido (regras decidem, LLM redige)** | **0,733** | **0,707** | **89** | 0,381 |

O benchmark discrimina onde o golden set saturava: o baseline deixa de ser perfeito
(8 dos 60 alertas ALTA descartados como falso positivo), mas o modelo de linguagem erra
o dobro (16 dos 60) e volta a colapsar o espaço de decisão em duas classes. Na
identificação da técnica, porém, o modelo supera a recuperação esparsa neste conjunto
(0,469 contra 0,381); no golden set, menor e com payloads mais diretos, ocorre o inverso
(0,600 contra 0,800).

### Validação externa em datasets públicos

| Conjunto | Natureza | n | F1-macro | Custo de erro |
|---|---|---|---|---|
| Golden set | Sintético, com payload e IP | 38 | 0,968 | 0 |
| Benchmark v1 | Sintético, com payload e IP, 20% ambíguo | 240 | 0,707 | 89 |
| UNSW-NB15 | Real, features de fluxo | 250 | 0,104 | 495 |
| CIC-IDS2017 (WebAttacks) | Real, features de fluxo | 141 | 0,000 | 305 |

O contraste é o principal achado do trabalho: o pipeline resolve a triagem de **alertas
textuais** e não resolve a classificação de **fluxos de rede** — duas tarefas que a
literatura frequentemente agrupa sob o mesmo rótulo. Os benchmarks públicos da área não
contêm o texto do alerta; o benchmark aberto deste trabalho preenche essa lacuna
(tese em [`docs/TESE.md`](./docs/TESE.md)). *Custo de erro* pondera o erro
operacionalmente caro: subestimar a gravidade de um alerta.

Análise completa em [`docs/RESULTADOS.md`](./docs/RESULTADOS.md).

## Como executar

Requisitos: Python 3.10+ (ou Docker). O caminho determinístico não precisa de GPU,
credenciais nem serviços externos, e reproduz todos os números deste README.

```bash
git clone https://github.com/digitalopentech/tcc-soc-copilot.git
cd tcc-soc-copilot
make setup       # cria .venv e instala as dependências
make demo        # triagem passo a passo de um alerta por classe
make eval        # ablação no golden set (38 alertas)
make benchmark   # ablação no benchmark aberto (240 alertas)
make test        # suíte de testes
```

Sem `make`, os mesmos comandos:

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
PYTHONPATH=src python -m soc_copilot.cli --demo
PYTHONPATH=src python -m soc_copilot.cli
PYTHONPATH=src python -m soc_copilot.cli --golden data/benchmark_v1.csv
pytest -q
```

Com Docker (ambiente isolado, idêntico ao usado nos experimentos):

```bash
docker build -t soc-copilot .
docker run --rm soc-copilot                                    # ablação determinística
docker run --rm soc-copilot python -m soc_copilot.cli --demo   # demonstração
docker run --rm soc-copilot pytest -q                          # testes
```

Os braços com modelo de linguagem exigem [Ollama](https://ollama.com) em execução com o
modelo `qwen3:4b` (`ollama pull qwen3:4b`). Levam de 17 s a 40 s por chamada ao modelo,
conforme o hardware (medições em Apple M3). A opção `--saida` grava as métricas no
formato JSON usado em `resultados/`:

```bash
make llm                                                # golden set → resultados/ablacao.json
PYTHONPATH=src python -m soc_copilot.cli --llm --golden data/benchmark_v1.csv --saida resultados/benchmark_v1.json
PYTHONPATH=src python -m soc_copilot.cli --llm --demo   # demonstração em modo híbrido
```

## Organização do repositório

```
├── README.md            # este documento (padrão ICA-cursos/PoCs)
├── Makefile             # atalhos: make setup | demo | eval | benchmark | llm | test | docker
├── Dockerfile           # ambiente reprodutível
├── requirements.txt     # dependências mínimas (pydantic, pandas, scikit-learn, numpy, pytest)
├── src/soc_copilot/     # pipeline: ingestão → enriquecimento → RAG → classificação · CLI
├── data/                # catálogo MITRE ATT&CK, golden set e benchmark_v1 rotulados
├── scripts/             # gerador reprodutível do benchmark (casos por fonte de telemetria)
├── resultados/          # métricas das ablações e validações externas (JSON)
├── tests/               # suíte pytest
├── docs/                # tese, arquitetura, resultados, proposta e estrutura da monografia
└── LICENSE              # MIT
```

## Documentação

- [Tese: o vazio de avaliação em triagem textual de alertas](./docs/TESE.md)
- [Arquitetura e decisões de projeto](./docs/ARQUITETURA.md)
- [Resultados experimentais e análise](./docs/RESULTADOS.md)
- [Estrutura da monografia](./docs/MONOGRAFIA_ESTRUTURA.md)
- [Proposta original](./docs/PROPOSTA_TCC.md) — escopo inicial; o braço em nuvem (AWS), o
  *fine-tuning* e a arquitetura multiagente ali previstos ficaram como trabalho futuro

---

Matrícula: 252.100.281

Pontifícia Universidade Católica do Rio de Janeiro

Curso de Pós Graduação *Inteligência Artificial Generativa & Large Language Models* / 2025.2
