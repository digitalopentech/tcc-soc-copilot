"""Interface de linha de comando para reproduzir os experimentos.

    python -m soc_copilot.cli           # ablacao deterministica (offline)
    python -m soc_copilot.cli --llm     # inclui os braços com modelo de linguagem
    python -m soc_copilot.cli --help
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .evaluate import executar_ablacao, formatar_matriz

RAIZ = Path(__file__).resolve().parent.parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="soc_copilot.cli",
        description="Reproduz os experimentos de ablação do copiloto de triagem.",
    )
    parser.add_argument("--golden", type=Path, default=RAIZ / "data" / "golden_set.csv",
                        help="caminho do conjunto de avaliação (padrão: data/golden_set.csv)")
    parser.add_argument("--llm", action="store_true",
                        help="inclui os braços com modelo de linguagem (requer Ollama)")
    parser.add_argument("--modelo", default="qwen3:4b",
                        help="modelo do Ollama a usar com --llm (padrão: qwen3:4b)")
    args = parser.parse_args(argv)

    if not args.golden.exists():
        print(f"erro: conjunto não encontrado em {args.golden}", file=sys.stderr)
        return 1

    chamar_modelo = None
    if args.llm:
        from .llm import conector_ollama, modelo_disponivel

        if not modelo_disponivel(args.modelo):
            print(f"erro: modelo '{args.modelo}' indisponível no Ollama local.",
                  file=sys.stderr)
            print(f"      inicie o serviço e execute: ollama pull {args.modelo}",
                  file=sys.stderr)
            return 1
        chamar_modelo = conector_ollama(args.modelo)

    resultados = executar_ablacao(args.golden, chamar_modelo=chamar_modelo)

    print(f"=== Ablação — {args.golden.name} ===")
    for metrica in resultados:
        print(" ", metrica.linha_resumo())
    print()
    print(f"Matriz de confusão — {resultados[-1].configuracao}")
    print(formatar_matriz(resultados[-1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
