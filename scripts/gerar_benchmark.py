"""Gera o benchmark aberto de triagem textual de alertas (data/benchmark_v1.csv).

Expande o golden_set.csv (38 alertas) para 240 alertas cobrindo seis fontes
de telemetria (IDS/IPS, WAF, EDR, Email GW, Cloud, Identity), com payload
textual rico e ~20% de casos ambíguos — o diferencial declarado na tese
(ver docs/TESE.md): benchmarks públicos de segurança não carregam o dado
textual que um modelo de linguagem precisa ler.

Cada caso é escrito manualmente (não gerado por template mecânico) para
garantir variedade real de payload. A semente fixa (42) só governa a
mistura/embaralhamento final e a distribuição de timestamps, mantendo o
processo reprodutível sem afetar o conteúdo dos casos.

Formato de saída idêntico ao golden_set.csv, mais duas colunas novas:
``ambiguo`` (0/1) e ``justificativa_rotulo`` (frase explicando o rótulo).
"""

from __future__ import annotations

import csv
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

SEMENTE = 42
RAIZ = Path(__file__).resolve().parents[1]
SAIDA = RAIZ / "data" / "benchmark_v1.csv"
CATALOGO_TECNICAS = RAIZ / "data" / "attack_techniques.json"

COLUNAS = [
    "id",
    "timestamp",
    "origem",
    "ip_origem",
    "ip_destino",
    "porta_destino",
    "protocolo",
    "payload",
    "descricao",
    "severidade_fonte",
    "prioridade_real",
    "tecnica_real",
    "ambiguo",
    "justificativa_rotulo",
]


@dataclass(frozen=True, slots=True)
class Caso:
    """Um alerta completo do benchmark, antes da atribuição de id/timestamp."""

    origem: str
    ip_origem: str
    ip_destino: str
    porta_destino: int
    protocolo: str
    payload: str
    descricao: str
    severidade_fonte: str
    prioridade_real: str
    tecnica_real: str
    ambiguo: int
    justificativa_rotulo: str


def _validar_tecnicas(casos: list[Caso]) -> None:
    """Garante que toda tecnica_real referenciada existe no catálogo ATT&CK."""
    import json

    catalogo = json.loads(CATALOGO_TECNICAS.read_text(encoding="utf-8"))
    ids_validos = {t["id"] for t in catalogo}
    invalidas = sorted(
        {c.tecnica_real for c in casos if c.tecnica_real and c.tecnica_real not in ids_validos}
    )
    if invalidas:
        raise ValueError(f"tecnica_real inexistente no catálogo ATT&CK: {invalidas}")


def gerar_casos() -> list[Caso]:
    """Reúne os casos de todas as fontes de telemetria em uma única lista."""
    from casos_ids import casos_ids
    from casos_waf import casos_waf
    from casos_edr import casos_edr
    from casos_email import casos_email
    from casos_cloud import casos_cloud
    from casos_identity import casos_identity

    todos = (
        casos_ids()
        + casos_waf()
        + casos_edr()
        + casos_email()
        + casos_cloud()
        + casos_identity()
    )
    return todos


def montar_dataframe(casos: list[Caso]) -> list[dict]:
    """Atribui id sequencial e timestamp determinístico (semente fixa) a cada caso."""
    rng = random.Random(SEMENTE)
    ordem = list(range(len(casos)))
    rng.shuffle(ordem)

    base = datetime(2026, 4, 6, 7, 0, 0)
    linhas: list[dict] = []
    cursor = base
    for posicao, indice_original in enumerate(ordem, start=1):
        caso = casos[indice_original]
        # Intervalo entre alertas aleatorizado mas reprodutível (1 a 12 min).
        cursor += timedelta(minutes=rng.randint(1, 12))
        linhas.append(
            {
                "id": f"BMK-{posicao:04d}",
                "timestamp": cursor.strftime("%Y-%m-%dT%H:%M:%S"),
                "origem": caso.origem,
                "ip_origem": caso.ip_origem,
                "ip_destino": caso.ip_destino,
                "porta_destino": caso.porta_destino,
                "protocolo": caso.protocolo,
                "payload": caso.payload,
                "descricao": caso.descricao,
                "severidade_fonte": caso.severidade_fonte,
                "prioridade_real": caso.prioridade_real,
                "tecnica_real": caso.tecnica_real,
                "ambiguo": caso.ambiguo,
                "justificativa_rotulo": caso.justificativa_rotulo,
            }
        )
    return linhas


def main() -> None:
    casos = gerar_casos()
    if len(casos) != 240:
        raise ValueError(f"esperado 240 casos, obtidos {len(casos)}")
    _validar_tecnicas(casos)

    linhas = montar_dataframe(casos)

    SAIDA.parent.mkdir(parents=True, exist_ok=True)
    with SAIDA.open("w", newline="", encoding="utf-8") as arquivo:
        escritor = csv.DictWriter(arquivo, fieldnames=COLUNAS)
        escritor.writeheader()
        escritor.writerows(linhas)

    print(f"gerado: {SAIDA} ({len(linhas)} linhas)")


if __name__ == "__main__":
    main()
