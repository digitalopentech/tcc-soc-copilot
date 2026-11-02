# Atalhos para executar o projeto. Veja `make help`.
#
# Usa o ambiente virtual em .venv/ se existir; caso contrário, o python3 do sistema.

PYTHON ?= $(shell test -x .venv/bin/python && echo .venv/bin/python || echo python3)
export PYTHONPATH := src

.PHONY: help setup demo eval benchmark llm test docker

help:        ## lista os alvos disponíveis
	@grep -E '^[a-z-]+: +##' $(MAKEFILE_LIST) | awk -F': +## ' '{printf "  make %-10s %s\n", $$1, $$2}'

setup:       ## cria o ambiente virtual e instala as dependências
	python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

demo:        ## triagem passo a passo de um alerta por classe de prioridade (offline)
	$(PYTHON) -m soc_copilot.cli --demo

eval:        ## ablação determinística no golden set (offline)
	$(PYTHON) -m soc_copilot.cli

benchmark:   ## ablação determinística no benchmark de 240 alertas (offline)
	$(PYTHON) -m soc_copilot.cli --golden data/benchmark_v1.csv

llm:         ## ablação completa com modelo de linguagem (requer Ollama com qwen3:4b)
	$(PYTHON) -m soc_copilot.cli --llm --saida resultados/ablacao.json

test:        ## suíte de testes
	$(PYTHON) -m pytest -q

docker:      ## constrói a imagem e executa a ablação determinística em contêiner
	docker build -t soc-copilot . && docker run --rm soc-copilot
