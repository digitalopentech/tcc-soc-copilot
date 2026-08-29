"""Enriquecimento determinístico de alertas — sem uso de LLM.

Este módulo é a resposta arquitetural à limitação conhecida de LLMs em
correlacionar eventos no tempo com precisão: classificação de IP, detecção
de padrões de ataque no payload e contagem de eventos por janela temporal
são resolvidos aqui com código determinístico (regex, ``ipaddress`` da
stdlib, aritmética de datas), e não delegados ao modelo de linguagem.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import timedelta
from typing import Any

from soc_copilot.models import Alerta

# Padrões de ataque conhecidos, buscados no payload/descrição do alerta.
# Cada entrada é (nome_do_padrao, regex compilada, case-insensitive).
_PADROES_ATAQUE: dict[str, re.Pattern[str]] = {
    "cmd_injection": re.compile(
        r"(;\s*(cat|ls|whoami|id|rm|curl|wget)\b|\|\s*(sh|bash)\b|`.*`|\$\(.*\)"
        r"|command\s+injection|/etc/shadow)",
        re.IGNORECASE,
    ),
    "webshell": re.compile(
        r"(webshell|shell\.php|cmd\s*=|c99\.php|r57\.php|eval\s*\(\s*\$_)",
        re.IGNORECASE,
    ),
    "exfiltracao": re.compile(
        r"(exfiltra|dns\s+tunnel|txt\s+query|base64.{0,20}\d{3,}\s*bytes"
        r"|upload\s+de\s+grande|\d{3,}\s*(mb|gb)\s+para)",
        re.IGNORECASE,
    ),
    "c2_beacon": re.compile(
        r"(beacon|c2\b|command\s+and\s+control|a\s+cada\s+\d+s\s+p/\s+dominio"
        r"|dominio\s+(novo|registrado\s+ha))",
        re.IGNORECASE,
    ),
    "desserializacao": re.compile(
        r"(deserializ|desserializ|rO0AB|java\.util\.|ObjectInputStream)",
        re.IGNORECASE,
    ),
    "acesso_suspeito": re.compile(
        r"(horario\s+atipico|geolocaliza\w*\s+incomum|conta\s+servico|svc_\w+"
        r"|login\s+\d{2}:\d{2}|autenticou\s+de\s+outro\s+pais)",
        re.IGNORECASE,
    ),
    "credential_stuffing": re.compile(
        r"(credential\s+stuffing|password\s+spray|\d{2,}\s+logins?\s+falhos"
        r"|failed\s+password.*\(\d{2,}x\))",
        re.IGNORECASE,
    ),
    "sqli": re.compile(
        r"(\bunion\s+select\b|\bor\s+1\s*=\s*1\b|--\s*$|;\s*drop\s+table\b"
        r"|\bselect\b.+\bfrom\b|'\s*or\s*'.*'\s*=\s*')",
        re.IGNORECASE,
    ),
    "xss": re.compile(
        r"(<script\b|javascript:|onerror\s*=|onload\s*=|<img\b[^>]*\bonerror\b)",
        re.IGNORECASE,
    ),
    "path_traversal": re.compile(
        r"(\.\./|\.\.\\|%2e%2e%2f|/etc/passwd|\\windows\\system32)",
        re.IGNORECASE,
    ),
    "brute_force": re.compile(
        r"(failed\s+login|falha\s+de\s+autentica|invalid\s+password|login\s+attempt"
        r"|tentativa\s+de\s+login)",
        re.IGNORECASE,
    ),
    "port_scan": re.compile(
        r"(port\s*scan|syn\s+scan|varredura\s+de\s+porta|nmap)",
        re.IGNORECASE,
    ),
}

# Portas comumente associadas a serviços web (usadas na correlação com SQLi/XSS).
PORTAS_WEB = frozenset({80, 443, 8080, 8443})

_JANELA_CURTA = timedelta(minutes=5)
_JANELA_LONGA = timedelta(minutes=60)

# Faixas privadas RFC1918 (IPv4) e o equivalente de uso local em IPv6
# (fc00::/7, RFC4193). Verificadas explicitamente em vez de usar
# ``is_private`` da stdlib, que também marca como privadas faixas de
# documentação/reservadas (ex.: 203.0.113.0/24, RFC5737) — o requisito
# pede especificamente RFC1918, não o conjunto amplo de "não roteável".
_REDES_PRIVADAS_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


def classificar_ip(endereco: str) -> str:
    """Classifica um IP como 'privado' (RFC1918), 'loopback' ou 'publico'.

    Usa a stdlib ``ipaddress`` para checar loopback (127.0.0.0/8, ::1) e
    as três faixas privadas RFC1918; qualquer outro endereço válido —
    incluindo faixas reservadas/documentação — é tratado como público,
    já que do ponto de vista da triagem de SOC o que importa é distinguir
    tráfego interno (RFC1918) do restante.
    """
    ip = ipaddress.ip_address(endereco)
    if ip.is_loopback:
        return "loopback"
    if any(ip in rede for rede in _REDES_PRIVADAS_RFC1918):
        return "privado"
    return "publico"


def detectar_padroes_payload(payload: str, descricao: str = "") -> list[str]:
    """Retorna os nomes dos padrões de ataque encontrados no payload/descrição.

    Busca por assinaturas de SQL Injection, XSS, path traversal, força
    bruta e varredura de portas via regex. O texto combinado (payload +
    descrição) é avaliado contra cada padrão independentemente.
    """
    texto_combinado = f"{payload}\n{descricao}"
    return [
        nome
        for nome, padrao in _PADROES_ATAQUE.items()
        if padrao.search(texto_combinado)
    ]


def correlacionar_temporal(alerta: Alerta, todos_alertas: list[Alerta]) -> dict[str, int]:
    """Conta eventos do mesmo IP de origem em janelas de 5 e 60 minutos.

    A janela é centrada no timestamp do alerta avaliado: conta-se quantos
    outros alertas do mesmo ``ip_origem`` ocorreram dentro de +/- 5 min e
    +/- 60 min. Esta é a correlação que um LLM tende a errar quando o
    contexto é longo — aqui é aritmética simples e exata.
    """
    contagem_curta = 0
    contagem_longa = 0
    for outro in todos_alertas:
        if outro.ip_origem != alerta.ip_origem:
            continue
        delta = abs(outro.timestamp - alerta.timestamp)
        if delta <= _JANELA_LONGA:
            contagem_longa += 1
            if delta <= _JANELA_CURTA:
                contagem_curta += 1
    return {
        "eventos_mesmo_ip_5min": contagem_curta,
        "eventos_mesmo_ip_60min": contagem_longa,
    }


def enriquecer(alerta: Alerta, todos_alertas: list[Alerta]) -> dict[str, Any]:
    """Gera o dicionário de features enriquecidas para um alerta.

    Combina classificação de IP, padrões de ataque detectados e
    correlação temporal — toda a informação estrutural que a etapa de
    classificação (regras ou LLM) consumirá, sem nenhuma chamada a modelo
    de linguagem.
    """
    features: dict[str, Any] = {
        "classe_ip_origem": classificar_ip(alerta.ip_origem),
        "classe_ip_destino": classificar_ip(alerta.ip_destino),
        "padroes_detectados": detectar_padroes_payload(alerta.payload, alerta.descricao),
        "porta_e_web": alerta.porta_destino in PORTAS_WEB,
    }
    features.update(correlacionar_temporal(alerta, todos_alertas))
    return features
