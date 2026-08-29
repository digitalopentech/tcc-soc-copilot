# Ambiente reprodutível do TCC — Copiloto de SOC 4.0
#
# Garante que os experimentos determinísticos rodem de forma idêntica em
# qualquer máquina, sem depender do Python local do avaliador.
#
#   docker build -t soc-copilot .
#   docker run --rm soc-copilot                 # executa a ablação determinística
#   docker run --rm soc-copilot pytest -q       # executa a suíte de testes
#
# O braço com modelo de linguagem NÃO roda aqui: exige Ollama no hospedeiro.
# Para incluí-lo, use --network=host e aponte OLLAMA_URL para o host.

FROM python:3.12-slim

LABEL org.opencontainers.image.title="soc-copilot" \
      org.opencontainers.image.description="Copiloto de triagem de alertas de SOC com RAG sobre MITRE ATT&CK" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Dependências primeiro: aproveita o cache de camadas do Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir pytest

COPY src/ ./src/
COPY data/ ./data/
COPY tests/ ./tests/
COPY pyproject.toml ./

ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1

# Usuário sem privilégios: boa prática em imagem de aplicação
RUN useradd --create-home --uid 1000 analista && chown -R analista:analista /app
USER analista

# Padrão: reproduz a ablação determinística e imprime as métricas
CMD ["python", "-c", "\
from pathlib import Path; \
from soc_copilot.evaluate import executar_ablacao, formatar_matriz; \
res = executar_ablacao(Path('data/golden_set.csv')); \
print('=== Ablacao deterministica (golden set) ==='); \
[print(' ', m.linha_resumo()) for m in res]; \
print(); print(formatar_matriz(res[-1]))"]
