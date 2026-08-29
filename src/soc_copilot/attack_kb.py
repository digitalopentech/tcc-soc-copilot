"""Base de conhecimento de técnicas MITRE ATT&CK.

Carrega o catálogo de técnicas a partir de ``data/attack_techniques.json``
e expõe uma interface simples (``Tecnica``, ``BaseAttack``) usada pelo
retriever e pelo classificador para fundamentar vereditos em referências
reconhecidas do framework ATT&CK.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Caminho padrão do catálogo, relativo à raiz do projeto (TCC-cybersecurity/).
_CAMINHO_PADRAO = Path(__file__).resolve().parents[2] / "data" / "attack_techniques.json"


def _normalizar_mitigacoes(valor: object) -> list[str]:
    """Aceita ``mitigacoes`` tanto como lista quanto como string separada por vírgula."""
    if valor is None:
        return []
    if isinstance(valor, list):
        return [str(item).strip() for item in valor]
    return [item.strip() for item in str(valor).split(",") if item.strip()]


@dataclass(frozen=True, slots=True)
class Tecnica:
    """Representa uma técnica do MITRE ATT&CK relevante para a triagem."""

    id: str
    nome: str
    tatica: str
    descricao: str
    mitigacoes: list[str] = field(default_factory=list)

    def texto_busca(self) -> str:
        """Concatena os campos textuais usados como corpus de recuperação."""
        return f"{self.nome} {self.tatica} {self.descricao}"


class BaseAttack:
    """Carrega e expõe o catálogo de técnicas MITRE ATT&CK."""

    def __init__(self, caminho: Path | None = None) -> None:
        self._caminho = Path(caminho) if caminho else _CAMINHO_PADRAO
        self._tecnicas: list[Tecnica] = self._carregar()

    def _carregar(self) -> list[Tecnica]:
        """Lê o JSON de técnicas, tolerando entradas malformadas."""
        if not self._caminho.exists():
            logger.warning(
                "catálogo ATT&CK não encontrado em %s; base ficará vazia", self._caminho
            )
            return []

        bruto = json.loads(self._caminho.read_text(encoding="utf-8"))
        entradas = bruto if isinstance(bruto, list) else bruto.get("tecnicas", [])

        tecnicas: list[Tecnica] = []
        for entrada in entradas:
            try:
                tecnicas.append(
                    Tecnica(
                        id=entrada["id"],
                        nome=entrada["nome"],
                        tatica=entrada.get("tatica", ""),
                        descricao=entrada.get("descricao", ""),
                        mitigacoes=_normalizar_mitigacoes(entrada.get("mitigacoes")),
                    )
                )
            except KeyError as erro:
                logger.warning("técnica ignorada por campo ausente: %s", erro)
                continue
        return tecnicas

    def listar(self) -> list[Tecnica]:
        """Retorna todas as técnicas carregadas."""
        return list(self._tecnicas)

    def buscar_por_id(self, tecnica_id: str) -> Tecnica | None:
        """Retorna a técnica com o ID informado, se existir."""
        return next((t for t in self._tecnicas if t.id == tecnica_id), None)


def listar(caminho: Path | None = None) -> list[Tecnica]:
    """Atalho de módulo: carrega o catálogo padrão e retorna todas as técnicas.

    Útil para uso rápido em scripts/notebooks, sem instanciar ``BaseAttack``
    explicitamente. Para reuso repetido (ex.: dentro do retriever), prefira
    instanciar ``BaseAttack`` uma única vez.
    """
    return BaseAttack(caminho).listar()
