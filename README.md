# Copiloto de SOC 4.0: triagem de alertas de segurança com RAG sobre MITRE ATT&CK

#### Aluno: [Leonardo Nunes](https://github.com/digitalopentech).
#### Orientador(a): *a definir*.

---

Trabalho apresentado ao curso [Inteligência Artificial Generativa & Large Language Models](https://ica.ele.puc-rio.br/cursos/ia-generativa-large-language-models/) (2025.2) como pré-requisito para conclusão de curso e obtenção de crédito na disciplina "Projeto LLM".

- [Link para o código](https://github.com/digitalopentech/tcc-soc-copilot).

- [Link para a monografia](./docs/MONOGRAFIA_ESTRUTURA.md).

---

### Resumo

Um Centro de Operações de Segurança (SOC) recebe milhares de alertas por dia de firewalls, IDS/IPS, EDR e SIEM. A maioria é falso positivo, mas cada alerta exige triagem — entender o que ocorreu, enriquecer com contexto e priorizar. O resultado é a *alert fatigue*: analistas saturados e alertas reais que passam despercebidos.

Este trabalho projeta, implementa e avalia um **copiloto de triagem de alertas** que recebe um alerta bruto, o enriquece de forma determinística, recupera contexto de ameaças da base **MITRE ATT&CK** por meio de RAG (*Retrieval-Augmented Generation*) e devolve uma classificação de prioridade acompanhada de justificativa rastreável e ação recomendada.

A contribuição central não é construir mais um copiloto — produtos comerciais já existem —, e sim **medir de forma independente e reproduzível** o que cada componente agrega. O sistema foi avaliado contra um *golden set* de 38 alertas rotulados por meio de experimentos de ablação que comparam três configurações: (i) um classificador determinístico baseado em regras explícitas sobre features extraídas do alerta; (ii) o mesmo pipeline acrescido de recuperação de contexto ATT&CK; e (iii) classificação por um modelo de linguagem (`qwen3:4b`, executado localmente).

Os resultados contrariam a expectativa inicial e constituem a principal contribuição empírica do trabalho. O baseline determinístico alcançou **F1-macro de 0,968 com custo de erro zero**, enquanto a configuração com modelo de linguagem obteve **F1-macro de 0,315**, classificando incorretamente como falso positivo 4 dos 12 alertas de prioridade máxima — o modo de falha mais grave em operações de segurança. A recuperação de contexto, por sua vez, demonstrou valor em uma dimensão distinta da priorização: elevou o acerto na identificação da técnica ATT&CK de 0,680 para 0,880.

Conclui-se que, para triagem de alertas estruturados, a arquitetura adequada é **híbrida**: o componente determinístico decide a prioridade, enquanto o modelo de linguagem enriquece, contextualiza e redige a justificativa destinada ao analista. Todo o material é reprodutível sem GPU ou serviços de nuvem.

### Abstract

A Security Operations Center (SOC) receives thousands of alerts per day from firewalls, IDS/IPS, EDR and SIEM systems. Most are false positives, yet each alert requires triage — understanding what happened, enriching it with context, and prioritizing it. The outcome is alert fatigue: saturated analysts and genuine alerts slipping through.

This work designs, implements and evaluates an **alert triage copilot** that takes a raw alert, enriches it deterministically, retrieves threat context from the **MITRE ATT&CK** knowledge base through Retrieval-Augmented Generation (RAG), and returns a priority classification with traceable justification and a recommended action.

The core contribution is not building yet another copilot — commercial products already exist — but **independently and reproducibly measuring** what each component adds. The system was evaluated against a golden set of 38 labeled alerts through ablation experiments comparing three configurations: (i) a deterministic rule-based classifier over features extracted from the alert; (ii) the same pipeline augmented with ATT&CK context retrieval; and (iii) classification by a language model (`qwen3:4b`, running locally).

The results contradict the initial expectation and constitute the main empirical contribution of this work. The deterministic baseline achieved a **macro-F1 of 0.968 with zero error cost**, whereas the language-model configuration reached a **macro-F1 of 0.315**, misclassifying 4 out of 12 highest-priority alerts as false positives — the most severe failure mode in security operations. Context retrieval, in turn, proved valuable along a dimension distinct from prioritization: it raised ATT&CK technique identification accuracy from 0.680 to 0.880.

We conclude that, for structured alert triage, the appropriate architecture is **hybrid**: the deterministic component decides priority, while the language model enriches, contextualizes and drafts the justification for the analyst. All material is reproducible without GPU or cloud services.

---

## Resultados

### Ablação no golden set (38 alertas)

| Configuração | Acurácia | F1-macro | Custo de erro | Acerto de técnica |
|---|---|---|---|---|
| Baseline (regras determinísticas) | 0,974 | 0,968 | **0** | 0,680 |
| Regras + RAG | 0,974 | 0,968 | **0** | **0,880** |
| LLM (`qwen3:4b`) + RAG | 0,447 | 0,315 | 70 | 0,840 |
| **Híbrido (regras decidem, LLM redige)** | **0,974** | **0,968** | **0** | **0,880** |

### Validação externa em datasets públicos

| Conjunto | Natureza | n | F1-macro | Custo de erro |
|---|---|---|---|---|
| Golden set | Sintético, com payload e IP | 38 | 0,968 | 0 |
| UNSW-NB15 | Real, features de fluxo | 250 | 0,104 | 495 |
| CIC-IDS2017 (WebAttacks) | Real, features de fluxo | 141 | 0,000 | 305 |

O contraste é o principal achado do trabalho: o pipeline resolve a triagem de **alertas
textuais** e não resolve a classificação de **fluxos de rede** — duas tarefas que a
literatura frequentemente agrupa sob o mesmo rótulo. *Custo de erro* pondera o erro
operacionalmente caro: subestimar a gravidade de um alerta.

Análise completa em [`docs/RESULTADOS.md`](./docs/RESULTADOS.md).

## Como reproduzir

Com Docker (reprodução integral e isolada):

```bash
docker build -t soc-copilot .
docker run --rm soc-copilot            # ablação determinística
docker run --rm soc-copilot pytest -q  # suíte de testes
```

Localmente (requer Python 3.10+):

```bash
# 1. Crie o ambiente e instale as dependências
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. Avaliação determinística (offline, sem modelo de linguagem)
PYTHONPATH=src python -m soc_copilot.cli

# 3. Suíte de testes
PYTHONPATH=src pytest tests/ -q
```

Para incluir o braço com modelo de linguagem é necessário [Ollama](https://ollama.com)
em execução com o modelo `qwen3:4b` (`ollama pull qwen3:4b`):

```bash
PYTHONPATH=src python -m soc_copilot.cli --llm
```

## Organização do repositório

```
├── Dockerfile           # ambiente reprodutível
├── src/soc_copilot/     # pipeline: ingestão → enriquecimento → RAG → classificação
├── data/                # base MITRE ATT&CK e golden set rotulado
├── resultados/          # métricas da ablação (JSON)
├── tests/               # suíte pytest
└── docs/                # arquitetura, resultados e estrutura da monografia
```

## Documentação

- [Arquitetura e decisões de projeto](./docs/ARQUITETURA.md)
- [Resultados experimentais e análise](./docs/RESULTADOS.md)
- [Estrutura da monografia](./docs/MONOGRAFIA_ESTRUTURA.md)
- [Proposta original](./PROPOSTA_TCC.md)

---

Matrícula: *a preencher*

Pontifícia Universidade Católica do Rio de Janeiro

Curso de Pós Graduação *Inteligência Artificial Generativa & Large Language Models*
