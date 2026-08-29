"""Conectores de modelo de linguagem para o classificador.

O pipeline nao depende de nenhum provedor especifico: qualquer funcao
`(prompt: str) -> str` serve como modelo. Aqui ficam os conectores usados
nos experimentos — Ollama local (padrao, reprodutivel offline) e um stub
deterministico para testes.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Callable

logger = logging.getLogger(__name__)

OLLAMA_URL = "http://localhost:11434/api/generate"


def conector_ollama(modelo: str = "llama3.2:3b", url: str = OLLAMA_URL,
                    temperatura: float = 0.0, timeout: int = 180,
                    formato_json: bool = True) -> Callable[[str], str]:
    """Devolve um callable que envia o prompt a um modelo local via Ollama.

    Usa apenas a stdlib para nao acrescentar dependencia ao projeto.
    Temperatura 0 por padrao: reprodutibilidade importa mais que criatividade
    numa tarefa de classificacao.
    """

    def chamar(prompt: str) -> str:
        payload: dict = {
            "model": modelo,
            "prompt": prompt,
            "stream": False,
            "think": False,  # desliga o raciocinio explicito em modelos que o suportam
            # num_predict alto: modelos de raciocinio consomem tokens antes da resposta
            "options": {"temperature": temperatura, "num_predict": 1200},
        }
        # format=json faz o Ollama restringir a decodificacao a JSON valido —
        # e a forma mais confiavel de obter saida estruturada de modelos pequenos.
        if formato_json:
            payload["format"] = "json"
        corpo = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=corpo,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read()).get("response", "")
        except (urllib.error.URLError, TimeoutError) as exc:
            logger.warning("falha ao chamar %s: %s", modelo, exc)
            return ""

    return chamar


def modelo_disponivel(modelo: str, url: str = "http://localhost:11434/api/tags") -> bool:
    """Verifica se o modelo esta instalado no Ollama local."""
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            nomes = {m["name"] for m in json.loads(resp.read()).get("models", [])}
        return modelo in nomes
    except Exception:
        return False
