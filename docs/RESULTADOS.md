# Resultados Experimentais

> Documento técnico de apoio à monografia. Todos os números foram medidos pela execução
> de `python -m soc_copilot.cli` (opcionalmente `--llm` e `--saida`) sobre
> `data/golden_set.csv` e `data/benchmark_v1.csv`, e estão persistidos em
> [`resultados/ablacao.json`](../resultados/ablacao.json) e
> [`resultados/benchmark_v1.json`](../resultados/benchmark_v1.json).

## 1. Protocolo experimental

| Parâmetro | Valor |
|---|---|
| Conjunto de avaliação | 38 alertas rotulados manualmente (`data/golden_set.csv`) |
| Distribuição | ALTA 12 · MÉDIA 10 · BAIXA 7 · FALSO_POSITIVO 9 |
| Base de conhecimento | 27 técnicas MITRE ATT&CK (`data/attack_techniques.json`); os braços com LLM foram medidos com o catálogo original de 10 técnicas — ver nota em §2 |
| Recuperador | TF-IDF + similaridade de cosseno, `k=3` |
| Modelo de linguagem | `qwen3:4b` via Ollama, `temperature=0`, `format=json` |
| Ambiente | Apple M3, 16 GB RAM, execução local sem GPU dedicada |
| Tempo total da ablação | 656 s (≈ 17 s por alerta no braço com LLM) |

O desenho é uma **ablação incremental**: cada configuração acrescenta um componente à
anterior, de modo que a diferença observada seja atribuível a esse componente.

## 2. Resultados consolidados

| # | Configuração | Acurácia | F1-macro | Custo de erro | Acerto de técnica |
|---|---|---|---|---|---|
| 1 | Baseline (regras determinísticas) | 0,974 | 0,968 | **0** | 0,680 |
| 2 | Regras + RAG | 0,974 | 0,968 | **0** | **0,800** |
| 3 | LLM + RAG | 0,447 | 0,315 | **70** | 0,840 ¹ |

¹ **Nota sobre o catálogo.** A ablação original foi executada com um catálogo de 10
técnicas ATT&CK. Na construção do benchmark (§10) o catálogo foi ampliado para 27
técnicas, e os braços determinísticos (1 e 2) foram remedidos com ele: o acerto de
técnica do braço 2 caiu de 0,880 para 0,800, sem alteração nas métricas de prioridade.
O braço 3 depende do modelo de linguagem e ainda não foi reexecutado com o catálogo
ampliado; seus números referem-se ao catálogo de 10 técnicas.

**Custo de erro** é uma métrica ponderada que penaliza o erro operacionalmente caro:
subestimar a gravidade de um alerta. Pesos: ALTA→FALSO_POSITIVO = 10; ALTA→BAIXA = 5;
MÉDIA→FALSO_POSITIVO = 3. O erro inverso (superestimar) não é penalizado, pois apenas
gera trabalho adicional ao analista, sem risco de incidente não detectado.

## 3. Desempenho por classe

### 3.1 Baseline e Regras + RAG (idênticos em prioridade)

| Classe | Precisão | Recall | F1 | Suporte |
|---|---|---|---|---|
| FALSO_POSITIVO | 0,900 | 1,000 | 0,947 | 9 |
| BAIXA | 1,000 | 0,857 | 0,923 | 7 |
| MÉDIA | 1,000 | 1,000 | 1,000 | 10 |
| ALTA | 1,000 | 1,000 | 1,000 | 12 |

### 3.2 LLM + RAG

| Classe | Precisão | Recall | F1 | Suporte |
|---|---|---|---|---|
| FALSO_POSITIVO | 0,300 | 1,000 | 0,462 | 9 |
| BAIXA | 0,000 | 0,000 | 0,000 | 7 |
| MÉDIA | 0,000 | 0,000 | 0,000 | 10 |
| ALTA | 1,000 | 0,667 | 0,800 | 12 |

## 4. Matrizes de confusão

Linhas = rótulo real; colunas = predição.

**Baseline / Regras + RAG**

```
              FALSO_   BAIXA   MEDIA    ALTA
real FALSO_        9       0       0       0
real BAIXA         1       6       0       0
real MEDIA         0       0      10       0
real ALTA          0       0       0      12
```

**LLM + RAG**

```
              FALSO_   BAIXA   MEDIA    ALTA
real FALSO_        9       0       0       0
real BAIXA         7       0       0       0
real MEDIA        10       0       0       0
real ALTA          4       0       0       8
```

## 5. Análise

### 5.1 O modelo de linguagem colapsou o espaço de decisão

O braço com LLM **não utilizou as classes BAIXA e MÉDIA em nenhuma das 38 decisões**:
classificou 30 alertas como FALSO_POSITIVO e 8 como ALTA. Esse comportamento binário
explica simultaneamente o recall perfeito em FALSO_POSITIVO (1,000) e a precisão baixa
na mesma classe (0,300) — o modelo acerta todos os falsos positivos verdadeiros porque
classifica quase tudo assim.

A consequência crítica: **4 dos 12 alertas de prioridade ALTA foram descartados como
falso positivo** (exfiltração de dados, beaconing de C2, entre outros). Em operação real,
esses são exatamente os incidentes que passam despercebidos — o modo de falha mais caro
de um SOC.

### 5.2 O RAG contribuiu na identificação da técnica, não na priorização

Este é o achado mais sutil e o mais útil. A recuperação de contexto ATT&CK elevou o
acerto de técnica de 0,680 para 0,800 (+17,6%) **sem alterar em nada as métricas de
prioridade**. Com o catálogo original de 10 técnicas o ganho era maior (0,680 → 0,880):
a ampliação para 27 técnicas introduziu candidatos semanticamente próximos e a
recuperação esparsa (TF-IDF) passou a confundi-los — evidência de que esse componente é
sensível ao tamanho do catálogo. A conclusão é que os dois problemas são independentes:

- **Priorizar** depende de sinais estruturados — severidade da fonte, classe do endereço
  de origem, correlação temporal, contexto operacional. São dados, não texto.
- **Identificar a técnica** depende de correspondência semântica entre a descrição do
  evento e a descrição da técnica. É exatamente onde a recuperação atua.

Trabalhos que reportam apenas uma métrica agregada não conseguem separar esses efeitos.

### 5.3 Por que o baseline é forte — e por que isso não o invalida

O baseline atinge F1-macro 0,968 porque as regras exploram um sinal que o golden set
fornece e que o LLM subutiliza: a **severidade atribuída pela ferramenta de origem**.
Esse é um dado legítimo e sempre disponível em um SIEM real; ignorá-lo para "dar chance"
ao modelo seria construir um espantalho.

O único erro do baseline é um alerta BAIXA classificado como FALSO_POSITIVO — erro barato,
sem penalidade no custo ponderado.

### 5.4 Ameaças à validade

Declaradas explicitamente, por honestidade metodológica:

1. **Tamanho da amostra.** n=38 é pequeno; intervalos de confiança seriam largos. Os
   resultados são **indicativos, não conclusivos**.
2. **Dados sintéticos.** O golden set foi construído para o trabalho. Ganha-se
   reprodutibilidade e ausência de dados sensíveis; perde-se a variabilidade e o ruído
   de tráfego real.
3. **Circularidade parcial no baseline.** As regras foram refinadas observando o
   desempenho no mesmo conjunto em que são avaliadas. Um conjunto de teste cego,
   construído após o congelamento das regras, é necessário para eliminar esse viés.
4. **Um único modelo.** `qwen3:4b` é um modelo pequeno e generalista. A conclusão
   **não** se estende a modelos maiores nem a modelos especializados em segurança.
5. **Ausência de ajuste extensivo de prompt.** Foi usado um único prompt, sem
   exploração sistemática de variantes ou *few-shot*.

## 6. Conclusões

1. Para triagem de alertas estruturados, **regras determinísticas sobre features bem
   escolhidas superam um modelo de linguagem pequeno**, a custo computacional
   desprezível e com latência de milissegundos contra ~17 s por alerta.
2. **O modelo pequeno é sistematicamente otimista**: subestima gravidade, o que é o
   viés mais perigoso possível neste domínio.
3. **A recuperação de contexto (RAG) tem valor comprovado**, mas em uma dimensão
   específica — enriquecimento semântico (identificação da técnica), não decisão.
4. O desenho arquitetural recomendado é **híbrido**: o componente determinístico decide
   a prioridade; o modelo de linguagem enriquece, contextualiza e redige a justificativa
   para o analista.

## 7. Trabalhos futuros derivados destes resultados

| Direção | Justificativa a partir do medido |
|---|---|
| Repetir com modelo especializado (ex.: Foundation-Sec-8B) | Testar se a especialização em segurança corrige o viés otimista |
| Ajuste fino (fine-tuning) para calibração | O erro é sistemático, não aleatório — candidato natural a correção supervisionada |
| Conjunto de teste cego e maior | Elimina a circularidade descrita em 5.4.3 — *parcialmente realizado*: benchmark de 240 alertas (§10) |
| LLM como redator, não decisor | Avaliar qualidade da justificativa com a prioridade fixada pelas regras — *realizado*: modo híbrido (§9.4) |
| Ingestão de dados reais (CIC-IDS2017, UNSW-NB15) | Validar fora do ambiente sintético — *realizado*: §8 e §9 |

---

# 8. Validação externa: UNSW-NB15

## 8.1 Motivação

A limitação mais séria declarada na seção 5.4 é que o golden set é sintético e pequeno.
Para testar a generalização, o pipeline foi avaliado contra o **UNSW-NB15**
(Moustafa & Slay, 2015), obtido via Kaggle (`dhoogla/unswnb15`) — 82.332 fluxos de rede
reais rotulados em nove categorias de ataque.

Foi usada uma **amostra estratificada de 250 fluxos** (25 por categoria), evitando que o
tráfego normal domine as métricas. O mapeamento categoria → prioridade segue o impacto
operacional: `Exploits`, `Backdoor`, `Shellcode` e `Worms` → ALTA; `Reconnaissance`,
`DoS` e `Generic` → MÉDIA; `Analysis` e `Fuzzers` → BAIXA; `Normal` → FALSO_POSITIVO.

## 8.2 Nota metodológica: vazamento de rótulo detectado e corrigido

A primeira versão do adaptador derivava o campo `severidade_fonte` da própria categoria
de ataque. O resultado foi acurácia de 0,900 — **artificial**: o classificador recebia a
resposta embutida na entrada, e as regras apenas a reproduziam. É o mesmo erro
metodológico que invalida silenciosamente muitos trabalhos aplicados.

A correção passou a derivar a severidade **exclusivamente de features do fluxo**
(número de conexões recentes a portas distintas, taxa de pacotes, volume de bytes,
presença de autenticação FTP, profundidade de transação HTTP) — como uma ferramenta real
faria, sem acesso ao rótulo. Os números abaixo referem-se à versão corrigida.

## 8.3 Resultados

| Configuração | Acurácia | F1-macro | Custo de erro | Acerto de técnica |
|---|---|---|---|---|
| Baseline (regras) | 0,204 | 0,104 | 495 | 0,000 |
| Regras + RAG | 0,204 | 0,104 | 495 | 0,018 |

Matriz de confusão (Regras + RAG):

```
              FALSO_   BAIXA   MEDIA    ALTA
real FALSO_        0      24       1       0
real BAIXA         0      48       1       1
real MEDIA         0      59       3      13
real ALTA          0      99       1       0
```

## 8.4 Análise: o colapso do baseline fora do domínio

O contraste com o golden set é o resultado mais informativo do trabalho:

| | Golden set (sintético) | UNSW-NB15 (real) |
|---|---|---|
| Acurácia | 0,974 | 0,204 |
| F1-macro | 0,968 | 0,104 |
| Custo de erro | 0 | 495 |

**99 dos 100 alertas de prioridade ALTA foram classificados como BAIXA.** A causa é
estrutural, não um defeito de implementação: o UNSW-NB15 **não contém payload nem
endereço IP** — apenas features estatísticas de fluxo. As regras do baseline foram
construídas sobre inspeção de payload (expressões regulares para SQLi, path traversal,
webshell) e classificação de endereço. Nenhum desses sinais existe no dataset real.

Sem payload, o baseline recai na severidade — que, calculada honestamente a partir do
comportamento do fluxo, classifica 230 dos 250 eventos como `low`, e a regra
correspondente atribui BAIXA a quase tudo.

## 8.5 Implicações — e revisão da conclusão anterior

Este experimento **qualifica de forma decisiva** a conclusão da seção 6:

1. **A superioridade do baseline é dependente de domínio, não geral.** Ele vence no
   golden set porque este fornece exatamente os sinais que as regras exploram. A
   afirmação "regras superam LLM na triagem" precisa ser lida como "regras superam LLM
   *quando os alertas contêm payload textual e endereçamento*".

2. **O experimento anterior tinha circularidade** (declarada em 5.4.3): regras
   refinadas e avaliadas no mesmo conjunto. O UNSW-NB15 funciona como o **conjunto de
   teste cego** que faltava, e revela o custo dessa circularidade.

3. **Alertas de fluxo e alertas de payload são problemas distintos.** Um copiloto de SOC
   real recebe ambos. A arquitetura precisa de features específicas por tipo de fonte —
   um classificador único sobre features de payload não transfere para telemetria de rede.

4. **É aqui que o aprendizado de máquina supervisionado se justifica.** Onde não há
   padrão textual a inspecionar, um modelo treinado sobre as features numéricas do fluxo
   é a abordagem adequada — e o próprio UNSW-NB15 é um benchmark consolidado para isso.
   Regras determinísticas não são substituto universal.

## 8.6 Reprodução

```bash
PYTHONPATH=src python -c "
import kagglehub
from pathlib import Path
from soc_copilot.datasets import carregar_unsw_nb15
p = Path(kagglehub.dataset_download('dhoogla/unswnb15'))
alertas, reais, tecnicas = carregar_unsw_nb15(next(p.rglob('*testing-set.parquet')), 25)
print(len(alertas), 'alertas carregados')
"
```

Requer credenciais do Kaggle configuradas. Resultados em
[`resultados/unsw_nb15.json`](../resultados/unsw_nb15.json).

---

# 9. Segunda validação externa: CIC-IDS2017 e o modo híbrido

## 9.1 CIC-IDS2017 (WebAttacks)

O CIC-IDS2017 (Sharafaldin et al., 2018) foi escolhido como segunda validação por conter
uma família de ataques **de aplicação web** — o domínio para o qual as regras do baseline
foram projetadas. A hipótese era que o baseline se recuperaria aqui.

Amostra estratificada de 141 fluxos do subconjunto WebAttacks (`dhoogla/cicids2017`):
61 ALTA (SQL Injection, XSS), 40 MÉDIA (Brute Force) e 40 FALSO_POSITIVO (Benign).

| Configuração | Acurácia | F1-macro | Custo de erro |
|---|---|---|---|
| Regras + RAG | **0,000** | **0,000** | 305 |

```
              FALSO_   BAIXA   MEDIA    ALTA
real FALSO_        0      37       3       0
real BAIXA         0       0       0       0
real MEDIA         0      36       0       4
real ALTA          0      61       0       0
```

**A hipótese foi refutada.** O desempenho foi nulo: nenhuma predição correta em 141
alertas. A causa é a mesma do UNSW-NB15, e mais evidente aqui — a distribuição pública
do CIC-IDS2017 é uma versão *no-metadata*, com 78 features estatísticas de fluxo e
**sem payload, sem endereço IP e sem URL**. Ser "ataque web" no rótulo não significa que
o dado contenha o texto do ataque.

O baseline classificou 134 dos 141 eventos como BAIXA, incluindo todos os 61 ataques de
prioridade máxima: sem texto para inspecionar e com severidade baixa estimada do fluxo,
a regra de menor gravidade absorve tudo.

## 9.2 Um achado sobre disponibilidade de dados

A busca sistemática por datasets públicos com **payload textual real** — conduzida sobre
o Kaggle e o Hugging Face Hub — não localizou nenhum conjunto consolidado e amplamente
adotado. Os benchmarks de referência da área (UNSW-NB15, CIC-IDS2017, CSE-CIC-IDS2018,
CIC-DDoS2019) são todos publicados como **features estatísticas de fluxo**.

A razão é compreensível: payload real contém dados pessoais, credenciais e conteúdo
sensível, o que inviabiliza a publicação aberta. A consequência para a pesquisa é
concreta e raramente explicitada: **abordagens baseadas em análise textual de alertas —
o que inclui a maior parte das aplicações de modelos de linguagem a logs de segurança —
não dispõem de benchmark público comparável ao que existe para análise de fluxo.**

Esta é uma limitação estrutural do campo, não deste trabalho, mas condiciona diretamente
o que pode ser validado externamente aqui.

## 9.3 Síntese das três avaliações

| Conjunto | Natureza | n | F1-macro | Custo de erro |
|---|---|---|---|---|
| Golden set | Sintético, com payload e IP | 38 | 0,968 | 0 |
| UNSW-NB15 | Real, features de fluxo | 250 | 0,104 | 495 |
| CIC-IDS2017 (Web) | Real, features de fluxo | 141 | 0,000 | 305 |

A leitura correta desta tabela não é "o sistema é ruim", e sim: **o pipeline resolve o
problema de triagem de alertas textuais e não resolve o de classificação de fluxos de
rede.** São duas tarefas distintas que a literatura frequentemente agrupa sob o mesmo
rótulo de "detecção de intrusão".

Para fluxos, a abordagem estabelecida e adequada é aprendizado supervisionado sobre as
features numéricas — e ambos os datasets são benchmarks consagrados justamente para isso.
Um copiloto de SOC em produção precisaria de **dois caminhos distintos** conforme a fonte
do alerta: inspeção textual para alertas de WAF, EDR e e-mail; modelo estatístico para
telemetria de fluxo de rede.

## 9.4 Resultado do modo híbrido (golden set)

A ablação completa, com o quarto braço implementando a arquitetura recomendada:

| # | Configuração | Acurácia | F1-macro | Custo de erro | Acerto de técnica |
|---|---|---|---|---|---|
| 1 | Baseline (regras) | 0,974 | 0,968 | 0 | 0,680 |
| 2 | Regras + RAG | 0,974 | 0,968 | 0 | 0,800 |
| 3 | LLM + RAG | 0,447 | 0,315 | 70 | 0,840 ¹ |
| 4 | **Híbrido (regras decidem, LLM redige)** | **0,974** | **0,968** | **0** | **0,800** |

¹ Medido com o catálogo de 10 técnicas (ver nota em §2). No modo híbrido, prioridade e
técnica vêm do braço 2 por construção; o modelo só redige a justificativa.

O modo híbrido **preserva integralmente a qualidade da decisão determinística** —
métricas idênticas às do braço 2 — enquanto substitui a justificativa gerada por
template pela redação do modelo de linguagem. Exemplo de saída real:

> "O alerta foi classificado como FALSO_POSITIVO porque a transferência de 2GB para
> storage interno em rede privada (10.0.2.50 → 10.0.4.20) é um padrão compatível com
> rotina de backup automático."

A garantia de que o modelo não pode alterar a gravidade é assegurada por teste
automatizado: uma resposta do modelo tentando rebaixar um alerta ALTA para BAIXA é
descartada, e a prioridade determinística prevalece.

## 9.5 Reprodutibilidade por contêiner

O repositório inclui um `Dockerfile` que reproduz os experimentos determinísticos sem
depender do ambiente Python local:

```bash
docker build -t soc-copilot .
docker run --rm soc-copilot            # executa a ablação e imprime as métricas
docker run --rm soc-copilot pytest -q  # executa a suíte de testes
```

A execução em contêiner foi verificada e reproduz exatamente os números determinísticos
da seção 2 (braços 1 e 2) e da seção 10.
O braço com modelo de linguagem não é executado no contêiner por depender de um serviço
Ollama no hospedeiro.

---

# 10. Benchmark aberto de triagem textual (benchmark_v1)

## 10.1 Motivação

As seções 8 e 9 mostram que os benchmarks públicos não contêm o texto do alerta, e a
seção 5.4 declara que o golden set é pequeno e saturado (o baseline erra um único
alerta). O `benchmark_v1` responde às duas limitações: é o conjunto proposto em
[`TESE.md`](./TESE.md) §4, gerado de forma reprodutível por `scripts/gerar_benchmark.py`.

| Parâmetro | Valor |
|---|---|
| Conjunto | `data/benchmark_v1.csv` — 240 alertas |
| Fontes de telemetria | IDS/IPS, WAF, EDR, gateway de e-mail, nuvem, identidade (40 por fonte) |
| Distribuição por fonte | ALTA 10 · MÉDIA 12 · BAIXA 8 · FALSO_POSITIVO 10 |
| Casos ambíguos | 49 (20,4%), cada um com `justificativa_rotulo` documentada |
| Catálogo ATT&CK | 27 técnicas |
| Modelo de linguagem | `qwen3:4b` via Ollama, `temperature=0`, `format=json` |

## 10.2 Resultados consolidados

| # | Configuração | Acurácia | F1-macro | Custo de erro | Acerto de técnica |
|---|---|---|---|---|---|
| 1 | Baseline (regras) | 0,733 | 0,707 | 89 | 0,106 |
| 2 | Regras + RAG | 0,733 | 0,707 | 89 | 0,381 |
| 3 | LLM + RAG | 0,438 | 0,333 | 367 | **0,469** |
| 4 | Híbrido (regras + LLM redige) | 0,733 | 0,707 | 89 | 0,381 |

## 10.3 Desempenho por classe

**Baseline / Regras + RAG / Híbrido** (idênticos em prioridade)

| Classe | Precisão | Recall | F1 | Suporte |
|---|---|---|---|---|
| FALSO_POSITIVO | 0,567 | 0,283 | 0,378 | 60 |
| BAIXA | 0,535 | 0,958 | 0,687 | 48 |
| MÉDIA | 0,868 | 0,917 | 0,892 | 72 |
| ALTA | 0,979 | 0,783 | 0,870 | 60 |

**LLM + RAG**

| Classe | Precisão | Recall | F1 | Suporte |
|---|---|---|---|---|
| FALSO_POSITIVO | 0,311 | 1,000 | 0,474 | 60 |
| BAIXA | 0,000 | 0,000 | 0,000 | 48 |
| MÉDIA | 1,000 | 0,014 | 0,027 | 72 |
| ALTA | 0,957 | 0,733 | 0,830 | 60 |

## 10.4 Matrizes de confusão

Linhas = rótulo real; colunas = predição.

**Baseline / Regras + RAG / Híbrido**

```
              FALSO_   BAIXA   MEDIA    ALTA
real FALSO_       17      37       5       1
real BAIXA         2      46       0       0
real MEDIA         3       3      66       0
real ALTA          8       0       5      47
```

**LLM + RAG**

```
              FALSO_   BAIXA   MEDIA    ALTA
real FALSO_       60       0       0       0
real BAIXA        48       0       0       0
real MEDIA        69       0       1       2
real ALTA         16       0       0      44
```

## 10.5 Análise

1. **O benchmark discrimina onde o golden set saturava.** O baseline cai de F1-macro
   0,968 para 0,707 e deixa de ter custo zero: 8 dos 60 alertas ALTA foram descartados
   como falso positivo e 37 dos 60 falsos positivos foram escalados para BAIXA. O
   primeiro é o erro caro; o segundo é o erro barato que o custo ponderado ignora de
   propósito. Os casos ambíguos cumprem a função para a qual foram escritos.

2. **O modelo de linguagem repete o padrão do golden set.** Colapsa o espaço de decisão
   em FALSO_POSITIVO e ALTA (BAIXA nunca é usada; MÉDIA, uma vez em 72) e descarta 16
   dos 60 alertas ALTA — o dobro do baseline — com custo de erro quatro vezes maior
   (367 contra 89). O viés otimista descrito em 5.1 não era artefato do conjunto pequeno.

3. **Na identificação da técnica, o modelo supera a recuperação esparsa.** O acerto de
   técnica do braço LLM (0,469) é superior ao de Regras + RAG (0,381), que por sua vez
   supera em muito o baseline sem recuperação (0,106). Com 27 técnicas e seis fontes
   heterogêneas, a correspondência lexical do TF-IDF perde para o raciocínio semântico
   do modelo. Isso reforça a divisão de trabalho da arquitetura híbrida — e sugere um
   refinamento: no modo híbrido atual a técnica vem do braço 2; delegá-la ao modelo,
   mantendo a prioridade nas regras, é a evolução natural a avaliar.

4. **A leitura conjunta com as seções 8 e 9 fecha o argumento.** Nos conjuntos reais de
   fluxo (sem texto) o pipeline é inútil; no conjunto sintético com texto, a comparação
   entre abordagens é informativa e reproduzível. O que falta ao campo não é mais um
   modelo, é o dado textual aberto — que este benchmark fornece.

## 10.6 Ameaças à validade específicas

- **Autoria única dos rótulos.** Os 240 casos e seus rótulos foram escritos pelo autor;
  não há concordância entre anotadores. A `justificativa_rotulo` torna cada decisão
  auditável, mas não a valida.
- **Regras e benchmark têm a mesma origem.** Os padrões de ataque cobertos pelas regras
  e pelos casos se sobrepõem, ainda que as regras não tenham sido alteradas após a
  geração do benchmark. Um conjunto escrito por terceiros é o teste definitivo.
- **Um único modelo pequeno**, como em 5.4.

## 10.7 Reprodução

```bash
PYTHONPATH=src python -m soc_copilot.cli --golden data/benchmark_v1.csv            # braços 1–2
PYTHONPATH=src python -m soc_copilot.cli --golden data/benchmark_v1.csv --llm \
    --saida resultados/benchmark_v1.json                                             # braços 1–4
```

Os braços determinísticos reproduzem exatamente
[`resultados/benchmark_v1.json`](../resultados/benchmark_v1.json).
