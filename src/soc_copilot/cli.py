"""Interface de linha de comando para reproduzir os experimentos.

    python -m soc_copilot.cli --demo                       # triagem passo a passo de um alerta por classe
    python -m soc_copilot.cli                              # ablacao deterministica (offline)
    python -m soc_copilot.cli --llm                        # inclui os braços com modelo de linguagem
    python -m soc_copilot.cli --saida resultados/x.json    # persiste as métricas em JSON
    python -m soc_copilot.cli --help
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable

from .attack_kb import listar
from .classifier import ClassificadorHibrido, ClassificadorRegras
from .enrich import enriquecer
from .evaluate import ORDEM, Metricas, carregar_golden, executar_ablacao, formatar_matriz
from .retriever import RetrieverTFIDF

RAIZ = Path(__file__).resolve().parent.parent.parent


def demonstrar(caminho: Path, chamar_modelo: Callable[[str], str] | None = None) -> None:
    """Mostra a triagem completa de um alerta por classe de prioridade.

    Para cada etapa do pipeline (normalização, enriquecimento, recuperação
    ATT&CK, decisão) imprime o que entrou e o que saiu, ao lado do rótulo
    real do conjunto — é a forma mais direta de entender o que o copiloto faz.
    """
    alertas, reais, _ = carregar_golden(caminho)
    retriever = RetrieverTFIDF(listar())
    if chamar_modelo is None:
        classificador, nome = ClassificadorRegras(), "regras"
    else:
        classificador, nome = ClassificadorHibrido(chamar_modelo, retriever=retriever), "híbrido"

    print(f"=== Demonstração — {caminho.name} · classificador: {nome} ===")
    for classe in ORDEM:
        indice = next((i for i, r in enumerate(reais) if r == classe.value), None)
        if indice is None:
            continue
        alerta = alertas[indice]
        feats = enriquecer(alerta, alertas)
        consulta = f"{alerta.descricao} {alerta.payload}".strip() or alerta.origem
        recuperadas = retriever.buscar(consulta, k=3)
        veredito = classificador.classificar(alerta, feats, [t for t, _ in recuperadas])
        acertou = "✔" if veredito.prioridade.value == classe.value else "✘"

        payload = alerta.payload if len(alerta.payload) <= 90 else alerta.payload[:87] + "..."
        padroes = ", ".join(feats.get("padroes_detectados", [])) or "nenhum"
        tecnicas = " · ".join(f"{t.id} {t.nome} ({s:.2f})" for t, s in recuperadas) or "nenhuma"

        print()
        print(f"[{alerta.id}]  rótulo real: {classe.value}")
        print(f"  1. alerta        : {alerta.origem} · {alerta.timestamp:%Y-%m-%d %H:%M} · "
              f"{alerta.ip_origem} → {alerta.ip_destino}:{alerta.porta_destino}/{alerta.protocolo}"
              f" · severidade da fonte: {alerta.severidade_fonte or '-'}")
        print(f"     descrição     : {alerta.descricao or '-'}")
        print(f"     payload       : {payload or '-'}")
        print(f"  2. enriquecimento: ip_origem={feats.get('classe_ip_origem')} · "
              f"padrões={padroes} · eventos do mesmo IP em 60 min: "
              f"{feats.get('eventos_mesmo_ip_60min', 0)}")
        print(f"  3. recuperação   : {tecnicas}")
        print(f"  4. veredito      : {veredito.prioridade.value} {acertou}  "
              f"(confiança {veredito.confianca:.2f} · modo {veredito.modo})")
        print(f"     técnica       : {veredito.tecnica_attack or '-'}")
        print(f"     justificativa : {veredito.justificativa}")
        print(f"     ação          : {veredito.acao_recomendada}")


def salvar_resultados(caminho: Path, resultados: list[Metricas], conjunto: Path,
                      modelo_llm: str | None) -> None:
    """Grava as métricas no formato JSON usado em ``resultados/``."""
    dados = {
        "dataset": conjunto.name,
        "modelo_llm": modelo_llm,
        "catalogo_tecnicas": len(listar()),
        "experimentos": [
            {
                "configuracao": m.configuracao,
                "acuracia": round(m.acuracia, 4),
                "f1_macro": round(m.f1_macro, 4),
                "custo_erro": m.custo_erro,
                "acerto_tecnica": round(m.acerto_tecnica, 4),
                "por_classe": {
                    classe: {k: (round(v, 4) if isinstance(v, float) else v)
                             for k, v in valores.items()}
                    for classe, valores in m.por_classe.items()
                },
                "matriz_confusao": m.matriz,
            }
            for m in resultados
        ],
    }
    caminho.parent.mkdir(parents=True, exist_ok=True)
    caminho.write_text(json.dumps(dados, ensure_ascii=False, indent=2) + "\n",
                       encoding="utf-8")


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
    parser.add_argument("--saida", type=Path, default=None,
                        help="grava as métricas em JSON (ex.: resultados/ablacao.json)")
    parser.add_argument("--demo", action="store_true",
                        help="mostra a triagem passo a passo de um alerta por classe de prioridade")
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

    if args.demo:
        demonstrar(args.golden, chamar_modelo)
        return 0

    resultados = executar_ablacao(args.golden, chamar_modelo=chamar_modelo)

    print(f"=== Ablação — {args.golden.name} ===")
    for metrica in resultados:
        print(" ", metrica.linha_resumo())
    print()
    print(f"Matriz de confusão — {resultados[-1].configuracao}")
    print(formatar_matriz(resultados[-1]))
    if args.saida:
        salvar_resultados(args.saida, resultados, args.golden,
                          args.modelo if args.llm else None)
        print(f"\nmétricas gravadas em {args.saida}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
