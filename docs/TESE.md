# A tese: o vazio de avaliação em triagem textual de alertas

> Documento de posicionamento. Consolida a contribuição central do trabalho e a
> evidência que a sustenta.

## 1. Enunciado

> **Não é possível avaliar de forma reproduzível o uso de modelos de linguagem na
> triagem de alertas de segurança, porque os benchmarks públicos da área — sem exceção
> relevante — não contêm o dado textual que esses modelos precisam ler.**

Deste enunciado decorrem duas consequências:

1. Resultados publicados sobre "LLMs para detecção de intrusão" que utilizam os
   benchmarks consagrados avaliam, na prática, um classificador numérico com o modelo
   de linguagem em papel decorativo — o ganho reportado não pode ser atribuído à
   capacidade linguística do modelo, pois não há linguagem no dado.
2. A comunidade carece de um recurso de avaliação adequado. Este trabalho o propõe.

## 2. Evidência

### 2.1 Levantamento sistemático

Busca conduzida sobre **Kaggle** e **Hugging Face Hub** (agosto de 2026) com sete termos
de consulta — *intrusion detection*, *security alert triage*, *SIEM alerts*, *SOC alerts*,
*web attack payload*, *security log analysis*, *network intrusion* — resultando em
**27 datasets únicos no Kaggle e 11 no Hugging Face**.

Os conjuntos mais adotados da área:

| Dataset | Adoção | Conteúdo | Texto de alerta? |
|---|---|---|---|
| UNSW-NB15 | ★336 | 49 features estatísticas de fluxo | ✘ |
| CIC-IDS2017 / CSE-CIC-IDS2018 | ★212 / ★46 | 78 features de fluxo (*no-metadata*) | ✘ |
| NSL-KDD | (referência clássica) | 41 features de conexão | ✘ |
| Edge-IIoTset | ★211 | features de tráfego IoT | ✘ |
| N-BaIoT | ★133 | features estatísticas de tráfego | ✘ |
| **Microsoft GUIDE** | ★68 | 13M alertas reais de SOC, 45 colunas | **✘ (ver 2.2)** |

### 2.2 O caso decisivo: Microsoft GUIDE

O **GUIDE** (Microsoft, 2024) é o conjunto mais próximo do problema real de triagem que
existe publicamente: 13 milhões de alertas de clientes corporativos, com o rótulo de
triagem atribuído por analistas (`IncidentGrade` ∈ {TruePositive, BenignPositive,
FalsePositive}), técnicas MITRE ATT&CK associadas e 45 colunas de contexto —
`AlertTitle`, `Url`, `FileName`, `FolderPath`, `RegistryKey`, `ApplicationName`.

À primeira vista, é exatamente o benchmark que faltaria. Uma inspeção dos campos revela
o contrário:

| Campo | Conteúdo real | Numérico |
|---|---|---|
| `AlertTitle` | `563`, `2`, `10807` | 100% |
| `Url` | `160396`, `100465` | 100% |
| `FileName` | `289573`, `14` | 100% |
| `FolderPath` | `117668`, `22` | 100% |
| `RegistryKey` | `1631`, `156` | 100% |

**Todo campo textual foi substituído por um identificador numérico anonimizado.** O
título do alerta — a informação que um analista lê primeiro e que um modelo de linguagem
processaria — é um inteiro sem semântica. Não há "SQL injection em formulário de login";
há `563`.

A anonimização é legítima e necessária: são dados de clientes reais. Mas o efeito
colateral é que **o benchmark mais relevante da área é inutilizável para avaliar modelos
de linguagem**, restando apenas como conjunto de features categóricas.

### 2.3 Consequência medida neste trabalho

O pipeline desenvolvido foi avaliado em três conjuntos:

| Conjunto | Natureza | F1-macro | Custo de erro |
|---|---|---|---|
| Golden set (deste trabalho) | Sintético, **com payload textual** | 0,968 | 0 |
| Benchmark v1 (deste trabalho) | Sintético, **com payload textual**, 20% ambíguo | 0,707 | 89 |
| UNSW-NB15 | Real, features de fluxo | 0,104 | 495 |
| CIC-IDS2017 (WebAttacks) | Real, features de fluxo | 0,000 | 305 |

A queda não indica fragilidade do pipeline: indica **ausência do insumo**. As regras de
inspeção textual e a recuperação semântica não têm sobre o que operar quando o alerta é
um vetor de estatísticas de fluxo. Um modelo de linguagem, no mesmo cenário, teria a
mesma limitação — com custo computacional muito superior.

## 3. Por que o vazio existe

A explicação é estrutural, não acidental:

- **Payload real é dado sensível.** Uma requisição HTTP maliciosa carrega parâmetros,
  cookies, tokens e, frequentemente, dados pessoais. Um e-mail de phishing contém
  remetentes e destinatários reais. Publicar esse conteúdo é inviável sob LGPD/GDPR.
- **A anonimização destrói exatamente o que interessa.** Como o GUIDE demonstra,
  preservar a privacidade exige remover a semântica — e a semântica é o insumo do modelo.
- **A tradição da área é numérica.** A pesquisa em detecção de intrusão consolidou-se
  sobre features de fluxo décadas antes dos modelos de linguagem, e os benchmarks
  refletem essa herança.

## 4. A contribuição proposta

Um **benchmark aberto de triagem textual de alertas**, com três componentes:

1. **Conjunto de dados sintético mas realista**, cobrindo múltiplas fontes de telemetria
   (IDS, WAF, EDR, gateway de e-mail, nuvem, identidade), com payload textual completo e
   casos deliberadamente ambíguos que exigem raciocínio contextual — não apenas
   correspondência de padrão.
2. **Protocolo de avaliação** que exige baseline determinístico como condição de
   validade, evitando que ganhos triviais sejam atribuídos ao modelo.
3. **Métrica de custo assimétrico**, que pondera o erro operacionalmente caro
   (subestimar gravidade) de forma distinta do erro barato (superestimar).

**O conjunto existe e foi medido.** `data/benchmark_v1.csv` contém 240 alertas de seis
fontes de telemetria (40 por fonte), 20,4% deles ambíguos e com justificativa de rótulo,
gerados de forma reprodutível por `scripts/gerar_benchmark.py`. Sobre ele, o baseline
determinístico obtém F1-macro 0,707 (custo de erro 89) e o modelo de linguagem
`qwen3:4b`, 0,333 (custo 367); na identificação da técnica ATT&CK o modelo supera a
recuperação esparsa (0,469 contra 0,381). Análise completa em
[`RESULTADOS.md`](./RESULTADOS.md) §10.

Ser sintético é condição de possibilidade, não limitação: é precisamente o que permite
distribuição aberta com payload íntegro. A validade externa é endereçada pela derivação
dos casos a partir de padrões de ataque documentados e pela cobertura de fontes.

## 5. Delimitação honesta

- Um benchmark sintético **não substitui** avaliação em dados de produção; ele torna
  possível a comparação reproduzível que hoje não existe.
- O realismo do conjunto é uma afirmação a ser sustentada por construção documentada e
  revisão, não por asserção.
- A tese trata de **triagem textual**. Para classificação de fluxos de rede, os
  benchmarks existentes são adequados e a abordagem estabelecida (aprendizado
  supervisionado sobre features) permanece a recomendada.
