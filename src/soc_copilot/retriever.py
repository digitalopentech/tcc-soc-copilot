"""Recuperação de técnicas MITRE ATT&CK relevantes para um alerta.

Implementa recuperação via TF-IDF (scikit-learn), 100% offline — sem
download de modelos ou chamadas de rede. É o retriever padrão do
pipeline (ver decisão D1 do design): reprodutibilidade em qualquer
máquina prevalece sobre a sofisticação de embeddings neurais.
"""

from __future__ import annotations

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from soc_copilot.attack_kb import Tecnica


class RetrieverTFIDF:
    """Recuperador de técnicas ATT&CK baseado em similaridade TF-IDF."""

    def __init__(self, tecnicas: list[Tecnica]) -> None:
        self._tecnicas = tecnicas
        self._vectorizer = TfidfVectorizer()
        self._matriz = None
        if tecnicas:
            corpus = [t.texto_busca() for t in tecnicas]
            self._matriz = self._vectorizer.fit_transform(corpus)

    def buscar(self, consulta: str, k: int = 3) -> list[tuple[Tecnica, float]]:
        """Retorna as ``k`` técnicas mais similares à consulta, com escore.

        O escore é a similaridade de cosseno entre o vetor TF-IDF da
        consulta e o de cada técnica, em ordem decrescente. Retorna lista
        vazia se a base de técnicas estiver vazia.
        """
        if not self._tecnicas or self._matriz is None:
            return []

        vetor_consulta = self._vectorizer.transform([consulta])
        similaridades = cosine_similarity(vetor_consulta, self._matriz)[0]

        indices_ordenados = similaridades.argsort()[::-1][:k]
        return [
            (self._tecnicas[indice], float(similaridades[indice]))
            for indice in indices_ordenados
            if similaridades[indice] > 0.0
        ]
