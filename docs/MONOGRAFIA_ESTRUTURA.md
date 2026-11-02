# Estrutura da Monografia

> Esqueleto de redação. Cada seção indica o conteúdo esperado e de onde vem o material
> (proposta, código ou experimento). Alinhar com o orientador antes de escrever.

## 1. Introdução (3-4 pág.)
- **Contexto**: volume de alertas em SOC, alert fatigue, custo do analista
- **Problema**: triagem manual não escala; falso positivo domina o volume
- **Pergunta de pesquisa**: um copiloto com RAG sobre ATT&CK triage alertas com
  qualidade utilizável — e quanto cada componente (enriquecimento, RAG, LLM) contribui?
- **Objetivos**: geral e específicos → `PROPOSTA_TCC.md` §3, **revisados**: o braço em
  nuvem (AWS), o *fine-tuning* e a arquitetura multiagente da proposta ficaram como
  trabalho futuro — declarar a evolução do escopo explicitamente
- **Contribuições**: pipeline reprodutível + metodologia de avaliação com baseline +
  benchmark aberto de triagem textual (`docs/TESE.md`)
- **Organização do texto**

## 2. Fundamentação Teórica (6-8 pág.)
- 2.1 Operações de segurança: SOC, SIEM, triagem, MTTD/MTTR
- 2.2 MITRE ATT&CK: táticas, técnicas, uso como taxonomia
- 2.3 Modelos de linguagem: transformers, prompting, saída estruturada
- 2.4 RAG: motivação, recuperação esparsa (TF-IDF/BM25) × densa (embeddings)
- 2.5 Agentes e guardrails; OWASP LLM Top 10 (prompt injection é ameaça direta aqui)
- 2.6 **RAG × conhecimento estruturado**: quando a taxonomia já é um grafo, discutir
  formatos correlacionados (ex.: OKF) como alternativa ao chunking — *citar como
  prática emergente, não como fundamento consolidado*

## 3. Trabalhos Relacionados (3-4 pág.)
- Comerciais: Microsoft Security Copilot, CrowdStrike Charlotte, SentinelOne Purple
- Open-source: AiSOC, AI_SOC, triagem com Ollama
- Prática de indústria: LLMs em análise de logs (Splunk, 2025) — arquitetura híbrida
- **A lacuna**: ninguém publica avaliação independente com baseline honesto
  → `PROPOSTA_TCC.md` §1.2

## 4. Metodologia (5-6 pág.)
- 4.1 Arquitetura do pipeline (4 estágios) — diagrama
- 4.2 Decisão de projeto: determinístico × probabilístico, e por quê
- 4.3 Base de conhecimento ATT&CK e estratégia de recuperação
- 4.4 Construção do golden set: critérios de rotulagem, casos-limite deliberados
      (ex.: pentest autorizado com payload real de ataque)
- 4.5 Protocolo experimental: ablação (regras → +RAG → +LLM)
- 4.6 Métricas: precisão/recall/F1 por classe, matriz de confusão, custo do erro
      assimétrico (classificar ALTA como falso positivo é o erro caro)
- 4.7 Construção do benchmark_v1: 240 alertas, seis fontes, 20% ambíguos com
      justificativa de rótulo; gerador reprodutível (`scripts/`) → `docs/TESE.md` §4

## 5. Implementação (4-5 pág.)
- 5.1 Modelos de dados e validação de esquema
- 5.2 Enriquecimento determinístico: por que a correlação temporal não é do LLM
- 5.3 Recuperação: TF-IDF offline como padrão; embeddings como ablação
- 5.4 Classificação: baseline por regras e o modo LLM com fallback
- 5.5 Defesa contra prompt injection: alerta como dado delimitado
- 5.6 Reprodutibilidade: ambiente, sementes, dados versionados

## 6. Resultados e Discussão (6-8 pág.)
- 6.1 Desempenho por configuração (tabela de ablação)
- 6.2 Matrizes de confusão e análise dos erros caros
- 6.3 Onde o RAG ajudou — e onde não fez diferença
- 6.4 Análise de casos difíceis do golden set
- 6.5 **Discussão crítica**: o que uma métrica alta *não* prova; risco de Goodhart;
      limites de um golden set pequeno e sintético
- 6.6 Custo, latência e implicações de implantação (local × nuvem)
- 6.7 Resultados no benchmark_v1 e contraste com o golden set → `docs/RESULTADOS.md` §10
- 6.8 Validação externa (UNSW-NB15, CIC-IDS2017) e a lacuna de dados textuais nos
      benchmarks públicos → `docs/RESULTADOS.md` §8–9, `docs/TESE.md`

## 7. Conclusão (2-3 pág.)
- Síntese das descobertas e resposta à pergunta de pesquisa
- **Limitações declaradas** (honestidade metodológica vale nota)
- Trabalhos futuros: braço AWS, fine-tuning, ingestão ao vivo, multiagente, técnica
  delegada ao modelo no modo híbrido (`docs/RESULTADOS.md` §10.5)

## Referências
ABNT. Mínimo esperado: 20-30 fontes, com predomínio de artigos revisados por pares
sobre posts de fornecedor (estes entram como "prática de indústria", devidamente marcados).

---

## Checklist de entrega (padrão ICA-cursos/PoCs)
- [x] README no template, sem comentários HTML
- [x] Resumo (PT) e Abstract (EN)
- [x] Código documentado e reprodutível
- [x] Nome do orientador e matrícula preenchidos
- [ ] Link do repositório final ajustado (as PoCs listadas ficam na organização
      `secretaria-ICA`; confirmar o procedimento com a secretaria)
- [ ] Monografia (linha opcional no template; removida do README até o texto existir —
      este arquivo é a estrutura planejada)
- [x] Reexecutar a ablação com `--llm` após a ampliação do catálogo
- [x] Versionar `resultados/benchmark_v1.json`
- [x] Adicionar arquivo `LICENSE` (MIT, como declara o `Dockerfile`)
