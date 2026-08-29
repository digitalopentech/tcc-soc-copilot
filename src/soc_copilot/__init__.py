"""Copiloto de triagem de alertas de SOC — núcleo do pipeline.

Pipeline: alerta bruto -> ingestão -> enriquecimento -> RAG ATT&CK ->
classificação -> veredito. Ver ``docs`` do TCC para o design completo.
"""

from soc_copilot.attack_kb import BaseAttack, Tecnica, listar
from soc_copilot.classifier import (ChamarModelo, ClassificadorHibrido,
                                    ClassificadorLLM, ClassificadorRegras)
from soc_copilot.enrich import (
    classificar_ip,
    correlacionar_temporal,
    detectar_padroes_payload,
    enriquecer,
)
from soc_copilot.ingest import carregar_alertas
from soc_copilot.models import Alerta, Prioridade, Veredito
from soc_copilot.retriever import RetrieverTFIDF

__all__ = [
    "Alerta",
    "BaseAttack",
    "ChamarModelo",
    "ClassificadorLLM",
    "ClassificadorRegras",
    "ClassificadorHibrido",
    "Prioridade",
    "RetrieverTFIDF",
    "Tecnica",
    "Veredito",
    "carregar_alertas",
    "classificar_ip",
    "correlacionar_temporal",
    "detectar_padroes_payload",
    "enriquecer",
    "listar",
]
