"""Modelos de dados do copiloto de triagem de SOC.

Define os contratos (schemas) usados em todo o pipeline: o alerta bruto
normalizado (``Alerta``) e o resultado da triagem (``Veredito``). Ambos
são modelos Pydantic v2, garantindo validação de entrada/saída em todas
as fronteiras do sistema (ingestão, enriquecimento, classificação).
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class Prioridade(str, Enum):
    """Nível de prioridade atribuído a um alerta pela triagem."""

    FALSO_POSITIVO = "FALSO_POSITIVO"
    BAIXA = "BAIXA"
    MEDIA = "MEDIA"
    ALTA = "ALTA"


class Alerta(BaseModel):
    """Alerta de segurança já normalizado para o formato canônico.

    Representa um evento bruto (ex.: IDS/IPS, firewall, WAF) após a
    etapa de ingestão, independente da fonte original.
    """

    id: str = Field(..., description="Identificador único do alerta.")
    timestamp: datetime = Field(..., description="Momento de ocorrência do evento.")
    origem: str = Field(..., description="Sistema/sensor que gerou o alerta.")
    ip_origem: str = Field(..., description="Endereço IP de origem do tráfego.")
    ip_destino: str = Field(..., description="Endereço IP de destino do tráfego.")
    porta_destino: int = Field(..., ge=0, le=65535, description="Porta de destino.")
    protocolo: str = Field(..., description="Protocolo de rede (TCP, UDP, ICMP...).")
    payload: str = Field(default="", description="Conteúdo/carga útil observada.")
    descricao: str = Field(default="", description="Descrição textual do evento.")
    severidade_fonte: str = Field(
        default="", description="Severidade original atribuída pela fonte."
    )

    @field_validator("ip_origem", "ip_destino")
    @classmethod
    def _normalizar_ip(cls, valor: str) -> str:
        """Valida e normaliza o endereço IP para sua forma canônica."""
        try:
            return str(ipaddress.ip_address(valor.strip()))
        except ValueError as erro:
            raise ValueError(f"endereço IP inválido: {valor!r}") from erro

    @field_validator("protocolo")
    @classmethod
    def _normalizar_protocolo(cls, valor: str) -> str:
        """Padroniza o protocolo em maiúsculas, sem espaços nas pontas."""
        return valor.strip().upper()


class Veredito(BaseModel):
    """Resultado da triagem de um alerta, gerado por regras ou por LLM."""

    alerta_id: str = Field(..., description="Referência ao Alerta.id avaliado.")
    prioridade: Prioridade = Field(..., description="Prioridade atribuída.")
    confianca: float = Field(
        ..., ge=0.0, le=1.0, description="Confiança do veredito, entre 0 e 1."
    )
    tecnica_attack: str | None = Field(
        default=None, description="ID da técnica MITRE ATT&CK associada, se houver."
    )
    justificativa: str = Field(..., description="Explicação textual do veredito.")
    acao_recomendada: str = Field(..., description="Próxima ação sugerida ao analista.")
    modo: str = Field(..., description="Origem do veredito: 'regras', 'llm' ou 'hibrido'.")

    @field_validator("modo")
    @classmethod
    def _validar_modo(cls, valor: str) -> str:
        """Restringe o modo aos valores suportados pelo pipeline."""
        modos_validos = {"regras", "llm", "hibrido"}
        if valor not in modos_validos:
            raise ValueError(f"modo deve ser um de {modos_validos}, recebido: {valor!r}")
        return valor
