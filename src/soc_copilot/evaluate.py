"""Avaliacao do copiloto contra o golden set, com experimentos de ablacao.

O objetivo nao e "obter F1 alto": e medir o que cada componente do pipeline
acrescenta sobre um baseline honesto. Sem baseline, uma metrica alta nao
distingue merito do modelo de facilidade da tarefa.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .attack_kb import listar
from .classifier import ClassificadorRegras
from .enrich import enriquecer
from .ingest import carregar_alertas
from .models import Alerta, Prioridade, Veredito
from .retriever import RetrieverTFIDF

ORDEM = [Prioridade.FALSO_POSITIVO, Prioridade.BAIXA, Prioridade.MEDIA, Prioridade.ALTA]

# Classificar um alerta critico como falso positivo e o erro caro: o incidente
# passa despercebido. O inverso apenas gera trabalho extra ao analista.
PESO_ERRO_CRITICO = {(Prioridade.ALTA, Prioridade.FALSO_POSITIVO): 10,
                     (Prioridade.ALTA, Prioridade.BAIXA): 5,
                     (Prioridade.MEDIA, Prioridade.FALSO_POSITIVO): 3}


@dataclass
class Metricas:
    """Metricas de uma configuracao do pipeline."""

    configuracao: str
    acuracia: float
    f1_macro: float
    por_classe: dict[str, dict[str, float]] = field(default_factory=dict)
    matriz: list[list[int]] = field(default_factory=list)
    custo_erro: int = 0
    acerto_tecnica: float = 0.0

    def linha_resumo(self) -> str:
        return (f"{self.configuracao:<28} acuracia={self.acuracia:.3f}  "
                f"F1-macro={self.f1_macro:.3f}  custo_erro={self.custo_erro:>3}  "
                f"tecnica={self.acerto_tecnica:.3f}")


def carregar_golden(caminho: Path) -> tuple[list[Alerta], list[str], list[str]]:
    """Le o golden set e devolve (alertas, prioridades reais, tecnicas reais)."""
    alertas = carregar_alertas(caminho)
    with open(caminho, encoding="utf-8") as fh:
        linhas = list(csv.DictReader(fh))
    reais = [l["prioridade_real"].strip() for l in linhas]
    tecnicas = [l.get("tecnica_real", "").strip() for l in linhas]
    return alertas, reais, tecnicas


def _matriz_confusao(reais: list[str], preditos: list[str]) -> list[list[int]]:
    idx = {p.value: i for i, p in enumerate(ORDEM)}
    m = [[0] * len(ORDEM) for _ in ORDEM]
    for r, p in zip(reais, preditos):
        if r in idx and p in idx:
            m[idx[r]][idx[p]] += 1
    return m


def _metricas_por_classe(reais: list[str], preditos: list[str]) -> dict[str, dict[str, float]]:
    saida: dict[str, dict[str, float]] = {}
    for cls in ORDEM:
        c = cls.value
        vp = sum(1 for r, p in zip(reais, preditos) if r == c and p == c)
        fp = sum(1 for r, p in zip(reais, preditos) if r != c and p == c)
        fn = sum(1 for r, p in zip(reais, preditos) if r == c and p != c)
        prec = vp / (vp + fp) if vp + fp else 0.0
        rec = vp / (vp + fn) if vp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        saida[c] = {"precisao": prec, "recall": rec, "f1": f1, "suporte": vp + fn}
    return saida


def avaliar(alertas: list[Alerta], reais: list[str], tecnicas_reais: list[str],
            classificar_fn: Callable[[Alerta, dict[str, Any]], Veredito],
            nome: str) -> Metricas:
    """Executa uma configuracao sobre todo o golden set e calcula as metricas."""
    preditos, tec_preditas = [], []
    for alerta in alertas:
        feats = enriquecer(alerta, alertas)
        veredito = classificar_fn(alerta, feats)
        preditos.append(veredito.prioridade.value)
        tec_preditas.append(veredito.tecnica_attack or "")

    acertos = sum(1 for r, p in zip(reais, preditos) if r == p)
    por_classe = _metricas_por_classe(reais, preditos)
    f1_macro = sum(v["f1"] for v in por_classe.values()) / len(por_classe)

    custo = 0
    for r, p in zip(reais, preditos):
        try:
            custo += PESO_ERRO_CRITICO.get((Prioridade(r), Prioridade(p)), 0)
        except ValueError:
            continue

    # Acerto de tecnica considerado apenas onde o golden set declara uma
    com_tecnica = [(t, p) for t, p in zip(tecnicas_reais, tec_preditas) if t]
    acerto_tec = (sum(1 for t, p in com_tecnica if t == p) / len(com_tecnica)) if com_tecnica else 0.0

    return Metricas(configuracao=nome, acuracia=acertos / len(reais), f1_macro=f1_macro,
                    por_classe=por_classe, matriz=_matriz_confusao(reais, preditos),
                    custo_erro=custo, acerto_tecnica=acerto_tec)


def executar_ablacao(caminho_golden: Path, chamar_modelo: Callable[[str], str] | None = None
                     ) -> list[Metricas]:
    """Roda os experimentos de ablacao: regras -> +RAG -> +LLM.

    O modo LLM so entra se `chamar_modelo` for fornecido; sem ele a avaliacao
    permanece 100% reprodutivel offline.
    """
    alertas, reais, tecnicas_reais = carregar_golden(caminho_golden)
    tecnicas = listar()
    retr = RetrieverTFIDF(tecnicas)
    regras = ClassificadorRegras()
    resultados: list[Metricas] = []

    # (1) Baseline: regras sobre features determinísticas, sem recuperacao
    resultados.append(avaliar(
        alertas, reais, tecnicas_reais,
        lambda a, f: regras.classificar(a, f, []),
        "1. Baseline (regras)"))

    # (2) Regras + RAG: a recuperacao passa a sugerir a tecnica ATT&CK
    def com_rag(alerta: Alerta, feats: dict[str, Any]) -> Veredito:
        consulta = f"{alerta.descricao} {alerta.payload}"
        recuperadas = [t for t, _ in retr.buscar(consulta, k=3)]
        return regras.classificar(alerta, feats, recuperadas)

    resultados.append(avaliar(alertas, reais, tecnicas_reais, com_rag, "2. Regras + RAG"))

    # (3) LLM + RAG (opcional)
    if chamar_modelo is not None:
        from .classifier import ClassificadorLLM
        llm = ClassificadorLLM(chamar_modelo=chamar_modelo, retriever=retr)

        def com_llm(alerta: Alerta, feats: dict[str, Any]) -> Veredito:
            consulta = f"{alerta.descricao} {alerta.payload}"
            recuperadas = [t for t, _ in retr.buscar(consulta, k=3)]
            return llm.classificar(alerta, feats, recuperadas)

        resultados.append(avaliar(alertas, reais, tecnicas_reais, com_llm, "3. LLM + RAG"))

        # (4) Hibrido: regras decidem a prioridade, o modelo redige a justificativa.
        # E a arquitetura recomendada pela evidencia dos braços anteriores.
        from .classifier import ClassificadorHibrido
        hibrido = ClassificadorHibrido(chamar_modelo=chamar_modelo, retriever=retr)

        def com_hibrido(alerta: Alerta, feats: dict[str, Any]) -> Veredito:
            consulta = f"{alerta.descricao} {alerta.payload}"
            recuperadas = [t for t, _ in retr.buscar(consulta, k=3)]
            return hibrido.classificar(alerta, feats, recuperadas)

        resultados.append(avaliar(alertas, reais, tecnicas_reais, com_hibrido,
                                  "4. Hibrido (regras + LLM redige)"))

    return resultados


def formatar_matriz(m: Metricas) -> str:
    """Matriz de confusao legivel em texto (linhas = real, colunas = predito)."""
    rot = [p.value[:6] for p in ORDEM]
    linhas = ["            " + "".join(f"{r:>8}" for r in rot)]
    for i, nome in enumerate(rot):
        linhas.append(f"real {nome:<7}" + "".join(f"{v:>8}" for v in m.matriz[i]))
    return "\n".join(linhas)
