"""Adaptadores para datasets publicos de seguranca.

Permite avaliar o pipeline fora do golden set sintetico, respondendo a uma
das ameacas a validade declaradas: generalizacao para dados reais.

UNSW-NB15 (Moustafa & Slay, 2015) contem fluxos de rede rotulados por
categoria de ataque. Diferentemente do golden set, NAO possui payload nem
endereco IP — sao features estatisticas de fluxo. O adaptador sintetiza uma
descricao textual a partir dessas features, o que permite reutilizar o
pipeline, mas com uma limitacao importante e declarada: as regras baseadas
em inspecao de payload nao tem sinal aqui.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from .models import Alerta

# Mapeamento categoria UNSW-NB15 -> prioridade de triagem.
# Criterio: impacto potencial se o evento for real, seguindo a logica
# operacional de um SOC (execucao remota > reconhecimento > ruido).
PRIORIDADE_POR_CATEGORIA: dict[str, str] = {
    "Normal": "FALSO_POSITIVO",
    "Analysis": "BAIXA",
    "Fuzzers": "BAIXA",
    "Reconnaissance": "MEDIA",
    "DoS": "MEDIA",
    "Generic": "MEDIA",
    "Exploits": "ALTA",
    "Backdoor": "ALTA",
    "Shellcode": "ALTA",
    "Worms": "ALTA",
}

# Categoria -> tecnica MITRE ATT&CK correspondente na base do projeto.
TECNICA_POR_CATEGORIA: dict[str, str] = {
    "Reconnaissance": "T1046",
    "Exploits": "T1190",
    "Backdoor": "T1071",
    "Shellcode": "T1059",
    "Worms": "T1190",
    "DoS": "T1499",
    "Generic": "T1190",
    "Fuzzers": "T1190",
    "Analysis": "T1046",
}

def _severidade_do_fluxo(linha) -> str:
    """Deriva a severidade a partir de features do FLUXO, nunca do rotulo.

    Derivar a severidade da categoria de ataque seria vazamento de rotulo: o
    classificador receberia a resposta na entrada. Aqui a severidade e
    estimada como uma ferramenta real faria — por heuristicas sobre o
    comportamento observado do trafego.
    """
    conexoes_portas = float(linha.get("ct_src_dport_ltm", 0) or 0)
    conexoes_servico = float(linha.get("ct_dst_sport_ltm", 0) or 0)
    bytes_origem = float(linha.get("sbytes", 0) or 0)
    taxa = float(linha.get("rate", 0) or 0)
    tentativas_ftp = float(linha.get("ct_ftp_cmd", 0) or 0)
    profundidade_http = float(linha.get("trans_depth", 0) or 0)

    indicadores = sum([
        conexoes_portas > 8,          # varredura horizontal
        conexoes_servico > 8,         # varredura vertical
        taxa > 100000,                # volume anomalo
        bytes_origem > 100000,        # transferencia grande de saida
        tentativas_ftp > 0,           # interacao FTP
        profundidade_http > 1,        # encadeamento HTTP incomum
    ])
    if indicadores >= 3:
        return "high"
    if indicadores == 2:
        return "medium"
    return "low"


def _descrever_fluxo(linha) -> str:
    """Sintetiza uma descricao textual legivel a partir das features do fluxo."""
    partes = [
        f"fluxo {linha['proto']}",
        f"servico {linha['service']}" if linha["service"] not in ("-", "") else "servico nao identificado",
        f"estado {linha['state']}",
        f"{int(linha['spkts'])} pacotes enviados e {int(linha['dpkts'])} recebidos",
        f"{int(linha['sbytes'])} bytes de origem e {int(linha['dbytes'])} de destino",
        f"duracao {float(linha['dur']):.3f}s",
    ]
    if float(linha.get("ct_src_dport_ltm", 0)) > 5:
        partes.append("multiplas conexoes recentes a portas distintas do mesmo destino")
    if int(linha.get("is_ftp_login", 0)) == 1:
        partes.append("autenticacao FTP presente")
    if float(linha.get("response_body_len", 0)) > 0:
        partes.append(f"corpo de resposta HTTP com {int(linha['response_body_len'])} bytes")
    return ", ".join(partes)


def carregar_unsw_nb15(caminho: Path, amostras_por_classe: int = 25,
                       semente: int = 42) -> tuple[list[Alerta], list[str], list[str]]:
    """Carrega uma amostra estratificada do UNSW-NB15 como alertas.

    Devolve (alertas, prioridades esperadas, tecnicas esperadas), no mesmo
    formato consumido por `evaluate.avaliar`.
    """
    import pandas as pd

    df = pd.read_parquet(caminho) if caminho.suffix == ".parquet" else pd.read_csv(caminho)

    # Amostragem estratificada: mesma quantidade por categoria, para que as
    # metricas por classe nao sejam dominadas pelo trafego normal.
    amostras = []
    for categoria, grupo in df.groupby("attack_cat"):
        n = min(amostras_por_classe, len(grupo))
        amostras.append(grupo.sample(n=n, random_state=semente))
    amostra = pd.concat(amostras).sample(frac=1, random_state=semente).reset_index(drop=True)

    base = datetime(2026, 4, 1, 9, 0)
    alertas, prioridades, tecnicas = [], [], []
    for i, linha in amostra.iterrows():
        categoria = str(linha["attack_cat"])
        prioridade = PRIORIDADE_POR_CATEGORIA.get(categoria, "MEDIA")
        alertas.append(Alerta(
            id=f"UNSW-{i:05d}",
            timestamp=base + timedelta(seconds=int(i) * 30),
            origem="IDS-fluxo",
            # O dataset nao traz IPs; usa-se faixa de documentacao (RFC5737)
            # para origem externa e RFC1918 para o destino interno.
            # IP derivado do indice, nao da categoria: derivar do rotulo seria
            # outra forma de vazamento.
            ip_origem=f"203.0.113.{(int(i) % 250) + 1}",
            ip_destino="10.0.1.100",
            porta_destino=0,
            protocolo=str(linha["proto"]).upper(),
            payload="",  # ausente por natureza do dataset
            descricao=_descrever_fluxo(linha),
            severidade_fonte=_severidade_do_fluxo(linha),
        ))
        prioridades.append(prioridade)
        tecnicas.append(TECNICA_POR_CATEGORIA.get(categoria, ""))

    return alertas, prioridades, tecnicas


# --------------------------------------------------------------------------
# CIC-IDS2017 (Sharafaldin et al., 2018)
# --------------------------------------------------------------------------
PRIORIDADE_CICIDS: dict[str, str] = {
    "Benign": "FALSO_POSITIVO",
    "Web Attack � Brute Force": "MEDIA",
    "Web Attack � XSS": "ALTA",
    "Web Attack � Sql Injection": "ALTA",
}

TECNICA_CICIDS: dict[str, str] = {
    "Web Attack � Brute Force": "T1110",
    "Web Attack � XSS": "T1190",
    "Web Attack � Sql Injection": "T1190",
}


def _severidade_cicids(linha) -> str:
    """Severidade estimada a partir do comportamento do fluxo HTTP.

    Como no adaptador do UNSW-NB15, a severidade NUNCA deriva do rotulo.
    """
    indicadores = sum([
        float(linha.get("Flow Packets/s", 0) or 0) > 1000,
        float(linha.get("Fwd Packets Length Total", 0) or 0) > 5000,
        float(linha.get("Flow Duration", 0) or 0) > 10_000_000,
        float(linha.get("Total Fwd Packets", 0) or 0) > 20,
    ])
    return "high" if indicadores >= 3 else ("medium" if indicadores == 2 else "low")


def carregar_cicids2017(caminho: Path, amostras_por_classe: int = 40,
                        semente: int = 42) -> tuple[list[Alerta], list[str], list[str]]:
    """Carrega amostra estratificada do subconjunto WebAttacks do CIC-IDS2017.

    Escolhido por ser a familia de ataque mais proxima do dominio do golden
    set (ataques a aplicacao web). Assim como o UNSW-NB15, esta versao do
    dataset contem apenas features de fluxo — sem payload nem IP.
    """
    import pandas as pd

    df = pd.read_parquet(caminho)
    amostras = []
    for rotulo, grupo in df.groupby("Label"):
        n = min(amostras_por_classe, len(grupo))
        amostras.append(grupo.sample(n=n, random_state=semente))
    amostra = pd.concat(amostras).sample(frac=1, random_state=semente).reset_index(drop=True)

    base = datetime(2026, 5, 4, 14, 0)
    alertas, prioridades, tecnicas = [], [], []
    for i, linha in amostra.iterrows():
        rotulo = str(linha["Label"])
        prioridade = PRIORIDADE_CICIDS.get(rotulo, "MEDIA")
        descricao = (
            f"fluxo HTTP protocolo {int(linha['Protocol'])}, "
            f"{int(linha['Total Fwd Packets'])} pacotes de ida e "
            f"{int(linha['Total Backward Packets'])} de volta, "
            f"{int(linha['Fwd Packets Length Total'])} bytes enviados, "
            f"duracao {float(linha['Flow Duration'])/1e6:.2f}s"
        )
        alertas.append(Alerta(
            id=f"CIC-{i:05d}",
            timestamp=base + timedelta(seconds=int(i) * 20),
            origem="WAF",
            ip_origem=f"198.51.100.{(int(i) % 250) + 1}",
            ip_destino="10.0.1.5",
            porta_destino=80,
            protocolo="TCP",
            payload="",
            descricao=descricao,
            severidade_fonte=_severidade_cicids(linha),
        ))
        prioridades.append(prioridade)
        tecnicas.append(TECNICA_CICIDS.get(rotulo, ""))

    return alertas, prioridades, tecnicas
