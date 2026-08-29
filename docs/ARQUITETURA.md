# Arquitetura do Sistema

> Documento técnico de apoio à monografia. Descreve as decisões de projeto, o fluxo de
> dados e as justificativas de cada escolha.

## 1. Princípio orientador

> **Tudo que precisa ser exato é código determinístico. O modelo de linguagem atua
> apenas onde raciocínio contextual agrega valor.**

Essa separação responde diretamente a limitações documentadas do uso de modelos de
linguagem em análise de logs (janela de contexto, correlação temporal fraca, custo em
escala, não-determinismo) e é o que permite que o sistema degrade com segurança quando
o modelo falha.

## 2. Visão geral do pipeline

```
   ┌─────────────────────────────────────────────────────────────────┐
   │  ENTRADA: alerta bruto (CSV ou JSON, esquema heterogêneo)       │
   └────────────────────────────┬────────────────────────────────────┘
                                ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  [1] ingest.py — NORMALIZAÇÃO                    determinístico  │
   │      mapeia aliases de coluna (src_ip, source_ip, ip_origem…)   │
   │      valida com Pydantic → objeto Alerta canônico               │
   │      linha malformada é descartada com aviso, sem interromper   │
   └────────────────────────────┬────────────────────────────────────┘
                                ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  [2] enrich.py — ENRIQUECIMENTO                  determinístico  │
   │      • classe do IP (RFC1918 privado / público / loopback)      │
   │      • 12 padrões de ataque por expressão regular               │
   │      • correlação temporal: eventos do mesmo IP em 5 e 60 min   │
   │      → dicionário de features                                   │
   └────────────────────────────┬────────────────────────────────────┘
                                ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  [3] retriever.py — RECUPERAÇÃO (RAG)            determinístico  │
   │      TF-IDF + cosseno sobre a base MITRE ATT&CK                 │
   │      → top-k técnicas relevantes ao alerta                      │
   └────────────────────────────┬────────────────────────────────────┘
                                ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  [4] classifier.py — DECISÃO                                     │
   │      ClassificadorRegras  → heurísticas explícitas (padrão)     │
   │      ClassificadorLLM     → modelo plugável (opcional)          │
   │                             ↳ falha → retry → fallback regras   │
   └────────────────────────────┬────────────────────────────────────┘
                                ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │  SAÍDA: Veredito validado por schema Pydantic                   │
   │  prioridade · confiança · técnica ATT&CK · justificativa · ação │
   └─────────────────────────────────────────────────────────────────┘
```

## 3. Componentes

| Módulo | Responsabilidade | Determinístico |
|---|---|---|
| `models.py` | Contratos de dados: `Alerta`, `Veredito`, `Prioridade` | ✔ |
| `ingest.py` | Normalização de fontes heterogêneas | ✔ |
| `enrich.py` | Features de rede, padrões e correlação temporal | ✔ |
| `attack_kb.py` | Carga da base MITRE ATT&CK | ✔ |
| `retriever.py` | Recuperação por similaridade TF-IDF | ✔ |
| `classifier.py` | Decisão de prioridade (regras ou LLM) | parcial |
| `llm.py` | Conector para Ollama (stdlib apenas) | ✘ |
| `evaluate.py` | Métricas e experimentos de ablação | ✔ |

## 4. Decisões de projeto

### D1 — Recuperação esparsa (TF-IDF) como padrão

**Decisão.** O recuperador padrão é TF-IDF com similaridade de cosseno, e não embeddings
densos.

**Justificativa.** Reprodutibilidade tem precedência sobre sofisticação em trabalho
acadêmico: TF-IDF executa offline, sem download de modelo e sem GPU. Qualquer avaliador
reproduz os resultados com `pip install -r requirements.txt`. Embeddings densos
permanecem como ablação futura.

### D2 — Baseline determinístico obrigatório

**Decisão.** O classificador por regras não é um artefato descartável: é o braço de
controle do experimento.

**Justificativa.** Sem baseline, uma métrica alta não distingue mérito do modelo de
facilidade da tarefa. Neste trabalho a decisão se mostrou determinante: o baseline
superou o modelo de linguagem, resultado que só é observável porque o controle existe.

### D3 — Saída estruturada com degradação segura

**Decisão.** Todo veredito é validado por schema Pydantic. Resposta inválida do modelo
aciona uma nova tentativa e, persistindo a falha, o sistema recorre ao classificador de
regras.

**Justificativa.** Um copiloto de SOC não pode interromper a operação porque o modelo
devolveu texto malformado. Durante os experimentos, essa decisão foi validada na
prática: em uma fase intermediária o modelo falhou em 100% das chamadas e o pipeline
continuou produzindo vereditos válidos.

### D4 — O alerta entra no prompt como dado, nunca como instrução

**Decisão.** O conteúdo do alerta é delimitado por marcadores explícitos
(`<ALERTA>…</ALERTA>`) e precedido de instrução para tratá-lo exclusivamente como dado
observado.

**Justificativa.** O payload de um alerta é conteúdo controlado por um adversário —
vetor direto de *prompt injection* (OWASP LLM01). Um atacante que soubesse do copiloto
poderia embutir instruções no próprio ataque para induzir classificação benigna.

### D5 — Correlação temporal fora do modelo

**Decisão.** A contagem de eventos correlacionados por IP e janela de tempo é calculada
em código, e o resultado é entregue pronto ao modelo.

**Justificativa.** Modelos de linguagem correlacionam eventos no tempo de forma
não confiável. Delegar a contagem a código elimina uma classe inteira de erro.

## 5. Modelo de dados

```python
class Prioridade(str, Enum):
    FALSO_POSITIVO, BAIXA, MEDIA, ALTA

class Alerta(BaseModel):
    id, timestamp, origem, ip_origem, ip_destino,
    porta_destino, protocolo, payload, descricao, severidade_fonte

class Veredito(BaseModel):
    alerta_id, prioridade, confianca (0–1),
    tecnica_attack, justificativa, acao_recomendada, modo
```

O campo `modo` (`"regras"` ou `"llm"`) torna auditável qual caminho produziu cada
decisão — requisito de rastreabilidade em operações de segurança.

## 6. Reprodutibilidade

| Requisito | Como é atendido |
|---|---|
| Sem GPU | Recuperação esparsa; modelo opcional |
| Sem rede | Dados e base ATT&CK versionados no repositório |
| Sem credenciais | Nenhum segredo no código; LLM local via Ollama |
| Determinismo | `temperature=0`; semente fixa na geração do golden set |
| Ambiente | `requirements.txt` com dependências mínimas |

## 7. Limitações arquiteturais conhecidas

1. **Enriquecimento passivo.** O sistema analisa apenas o que consta no alerta; não
   consulta fontes externas (reputação de IP, CVE). Integração via MCP é evolução natural.
2. **Base ATT&CK reduzida.** Dez técnicas cobrem o golden set, mas não o catálogo real.
3. **Sem estado entre execuções.** Cada lote é independente; não há memória de longo
   prazo sobre campanhas persistentes.
4. **Correlação limitada ao IP de origem.** Não há correlação por usuário, host ou
   sessão.
