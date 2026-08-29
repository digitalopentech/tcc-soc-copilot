"""Ingestão e normalização de alertas de fontes heterogêneas.

Fontes de segurança (IDS, firewall, WAF, SIEM) raramente usam os mesmos
nomes de coluna. Este módulo mapeia aliases conhecidos para o esquema
canônico de ``Alerta`` e tolera linhas malformadas sem interromper a
carga do lote inteiro — comportamento essencial em um pipeline de SOC,
onde um único registro corrompido não pode derrubar a triagem.
"""

from __future__ import annotations

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from soc_copilot.models import Alerta

logger = logging.getLogger(__name__)

# Mapeamento de aliases de coluna -> campo canônico de Alerta.
# Cada campo canônico pode ser alimentado por várias variações de nome
# encontradas em exports reais de ferramentas de segurança.
_ALIASES: dict[str, tuple[str, ...]] = {
    "id": ("id", "alert_id", "event_id", "uuid"),
    "timestamp": ("timestamp", "time", "datetime", "data_hora", "event_time"),
    "origem": ("origem", "source", "sensor", "fonte", "src_sensor"),
    "ip_origem": ("ip_origem", "src_ip", "source_ip", "ip_src", "srcaddr"),
    "ip_destino": ("ip_destino", "dst_ip", "dest_ip", "destination_ip", "ip_dst", "dstaddr"),
    "porta_destino": ("porta_destino", "dst_port", "dest_port", "destination_port", "dport"),
    "protocolo": ("protocolo", "protocol", "proto"),
    "payload": ("payload", "payload_data", "raw_payload", "conteudo"),
    "descricao": ("descricao", "description", "msg", "message", "signature"),
    "severidade_fonte": ("severidade_fonte", "severity", "priority", "severidade"),
}

# Campos obrigatórios: sem eles não é possível montar um Alerta válido.
_CAMPOS_OBRIGATORIOS = (
    "id",
    "timestamp",
    "origem",
    "ip_origem",
    "ip_destino",
    "porta_destino",
    "protocolo",
)


def _construir_mapa_colunas(colunas_disponiveis: list[str]) -> dict[str, str]:
    """Associa cada campo canônico à coluna real presente no arquivo.

    Retorna um dicionário {campo_canonico: nome_coluna_real}, considerando
    apenas os campos para os quais alguma coluna correspondente foi
    encontrada (comparação case-insensitive, ignorando espaços).
    """
    colunas_normalizadas = {c.strip().lower(): c for c in colunas_disponiveis}
    mapa: dict[str, str] = {}
    for campo_canonico, aliases in _ALIASES.items():
        for alias in aliases:
            if alias in colunas_normalizadas:
                mapa[campo_canonico] = colunas_normalizadas[alias]
                break
    return mapa


def _parsear_timestamp(valor: Any) -> datetime:
    """Converte string/número em ``datetime``, aceitando formatos comuns."""
    if isinstance(valor, datetime):
        return valor
    if isinstance(valor, (int, float)):
        return datetime.fromtimestamp(valor)
    texto = str(valor).strip()
    # datetime.fromisoformat cobre "YYYY-MM-DDTHH:MM:SS" e variações com offset.
    try:
        return datetime.fromisoformat(texto.replace("Z", "+00:00"))
    except ValueError:
        pass
    formatos_alternativos = (
        "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    )
    for formato in formatos_alternativos:
        try:
            return datetime.strptime(texto, formato)
        except ValueError:
            continue
    raise ValueError(f"timestamp em formato não reconhecido: {valor!r}")


def _linha_para_alerta(linha: dict[str, Any], mapa_colunas: dict[str, str]) -> Alerta:
    """Converte uma linha bruta (dict) em ``Alerta``, aplicando o mapa de aliases."""
    dados: dict[str, Any] = {}
    for campo_canonico, coluna_real in mapa_colunas.items():
        dados[campo_canonico] = linha.get(coluna_real)

    faltantes = [c for c in _CAMPOS_OBRIGATORIOS if not dados.get(c)]
    if faltantes:
        raise ValueError(f"campos obrigatórios ausentes: {faltantes}")

    dados["timestamp"] = _parsear_timestamp(dados["timestamp"])
    dados["porta_destino"] = int(dados["porta_destino"])
    dados["payload"] = dados.get("payload") or ""
    dados["descricao"] = dados.get("descricao") or ""
    dados["severidade_fonte"] = dados.get("severidade_fonte") or ""

    return Alerta(**dados)


def _carregar_linhas_csv(caminho: Path) -> list[dict[str, Any]]:
    """Lê um arquivo CSV e retorna a lista de linhas como dicionários."""
    with caminho.open("r", encoding="utf-8-sig", newline="") as arquivo:
        return list(csv.DictReader(arquivo))


def _carregar_linhas_json(caminho: Path) -> list[dict[str, Any]]:
    """Lê um arquivo JSON (lista de objetos ou objeto único) e retorna lista de dicts."""
    conteudo = json.loads(caminho.read_text(encoding="utf-8"))
    if isinstance(conteudo, dict):
        # Suporta tanto lista na raiz quanto objeto com chave "alertas"/"data".
        for chave in ("alertas", "alerts", "data", "items"):
            if chave in conteudo and isinstance(conteudo[chave], list):
                return conteudo[chave]
        return [conteudo]
    if isinstance(conteudo, list):
        return conteudo
    raise ValueError("JSON de alertas deve ser uma lista de objetos ou um objeto único")


def carregar_alertas(caminho: Path) -> list[Alerta]:
    """Carrega alertas de um arquivo CSV ou JSON com nomes de coluna heterogêneos.

    Linhas malformadas (campo obrigatório ausente, IP inválido, timestamp
    ilegível etc.) são ignoradas com aviso de log — a carga do restante
    do lote não é interrompida.
    """
    caminho = Path(caminho)
    if not caminho.exists():
        raise FileNotFoundError(f"arquivo de alertas não encontrado: {caminho}")

    sufixo = caminho.suffix.lower()
    if sufixo == ".csv":
        linhas = _carregar_linhas_csv(caminho)
    elif sufixo == ".json":
        linhas = _carregar_linhas_json(caminho)
    else:
        raise ValueError(f"formato de arquivo não suportado: {sufixo} (use .csv ou .json)")

    if not linhas:
        logger.warning("arquivo %s não contém registros", caminho)
        return []

    mapa_colunas = _construir_mapa_colunas(list(linhas[0].keys()))
    campos_sem_mapa = [c for c in _CAMPOS_OBRIGATORIOS if c not in mapa_colunas]
    if campos_sem_mapa:
        logger.warning(
            "nenhuma coluna reconhecida para os campos obrigatórios %s em %s",
            campos_sem_mapa,
            caminho,
        )

    alertas: list[Alerta] = []
    for numero_linha, linha in enumerate(linhas, start=1):
        try:
            alertas.append(_linha_para_alerta(linha, mapa_colunas))
        except (ValueError, TypeError, ValidationError) as erro:
            logger.warning(
                "linha %d de %s ignorada por erro de normalização: %s",
                numero_linha,
                caminho,
                erro,
            )
            continue

    return alertas
