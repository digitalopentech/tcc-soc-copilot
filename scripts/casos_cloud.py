"""Casos de telemetria Cloud (AWS/Azure) para o benchmark.

40 alertas: 10 ALTA, 12 MEDIA, 8 BAIXA, 10 FALSO_POSITIVO — 8 ambiguos (20%).
"""

from __future__ import annotations


def casos_cloud() -> list:
    from gerar_benchmark import Caso

    casos = [
        # --- ALTA (10) ---
        Caso(
            "Cloud", "203.0.113.55", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"PutBucketAcl","userIdentity":{"arn":"arn:aws:iam::111122223333:user/app-deploy"},"requestParameters":{"bucketName":"prod-clientes-docs","acl":"public-read"}}',
            "Alteracao de ACL de bucket de producao com dados de clientes para leitura publica",
            "critical", "ALTA", "T1530", 0,
            "bucket contendo documentos de clientes alterado para acesso publico e exposicao critica de dados.",
        ),
        Caso(
            "Cloud", "198.51.100.66", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"CreateAccessKey","userIdentity":{"arn":"arn:aws:iam::111122223333:user/root"},"sourceIPAddress":"198.51.100.66","additionalEventData":{"MFAUsed":"No"}}',
            "Criacao de chave de acesso para a conta root sem uso de MFA",
            "critical", "ALTA", "T1078.004", 0,
            "criacao de credencial de acesso programatico para a conta root, sem MFA, e violacao critica de controle de identidade.",
        ),
        Caso(
            "Cloud", "192.0.2.88", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"AttachUserPolicy","requestParameters":{"userName":"app-readonly","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"},"userIdentity":{"arn":"arn:aws:iam::111122223333:user/app-readonly"}}',
            "Escalonamento de privilegio: usuario anexa a si mesmo a politica AdministratorAccess",
            "critical", "ALTA", "T1098", 0,
            "auto-escalonamento de privilegio para acesso administrativo total e indicio direto de comprometimento de conta IAM.",
        ),
        Caso(
            "Cloud", "203.0.113.77", "0.0.0.0", 443, "HTTPS",
            "AWS Console Sign-In: usuario carlos.dev, regiao de login ap-southeast-2 (Sydney), primeira ocorrencia em 14 meses de historico (padrao usual: sa-east-1)",
            "Login no console de nuvem a partir de regiao geografica jamais utilizada pela organizacao",
            "high", "ALTA", "T1078.004", 0,
            "regiao de login completamente atipica para o historico do usuario e forte indicio de credencial comprometida.",
        ),
        Caso(
            "Cloud", "0.0.0.0", "0.0.0.0", 443, "HTTPS",
            'GitHub secret scanning alert: chave AWS ativa AKIAJ7X3K9M2N4P5Q6R7 commitada em repositorio publico "empresa/api-gateway", branch main, com permissoes de producao anexadas (verificado via GetCallerIdentity)',
            "Chave de acesso AWS de producao commitada em repositorio publico do GitHub",
            "critical", "ALTA", "T1552", 0,
            "chave com permissoes de producao exposta publicamente e verificada como ativa configura vazamento critico de credencial.",
        ),
        Caso(
            "Cloud", "198.51.100.101", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"DisableMFADevice","userIdentity":{"arn":"arn:aws:iam::111122223333:user/financeiro-admin"},"sourceIPAddress":"198.51.100.101"} seguido por login sem MFA 4 minutos depois',
            "Desabilitacao de MFA de conta administrativa seguida imediatamente de novo login",
            "critical", "ALTA", "T1098", 0,
            "sequencia de desabilitar MFA e logar em seguida e padrao classico de tomada de controle de conta privilegiada.",
        ),
        Caso(
            "Cloud", "192.0.2.120", "0.0.0.0", 443, "HTTPS",
            'Azure AD Sign-in log: usuario financeiro@empresa.onmicrosoft.com autenticado de IP 192.0.2.120 (Rússia) 8 minutos apos autenticacao de IP 10.0.1.50 (Sao Paulo) -- distancia incompativel com tempo de viagem',
            "Impossible travel: autenticacoes da mesma conta em geografias incompativeis em curto intervalo",
            "critical", "ALTA", "T1078.004", 0,
            "impossibilidade fisica de deslocamento entre as duas geografias no intervalo registrado confirma comprometimento de credencial.",
        ),
        Caso(
            "Cloud", "203.0.113.144", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"CreateUser","requestParameters":{"userName":"backup-svc-tmp"}} seguido em 90s por {"eventName":"CreateAccessKey"} e {"eventName":"AttachUserPolicy","policyArn":"...AdministratorAccess"} — usuario criado, chaveado e privilegiado em sequencia automatizada',
            "Sequencia automatizada de criacao de usuario backdoor com privilegio administrativo completo",
            "critical", "ALTA", "T1098", 0,
            "velocidade e sequencia das tres acoes (criar usuario, gerar chave, anexar admin) e assinatura de script automatizado de persistencia maliciosa, nao acao manual humana.",
        ),
        Caso(
            "Cloud", "198.51.100.155", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: 340 chamadas de list-buckets, describe-instances, list-users, get-account-authorization-details em 4 minutos, mesma credencial de acesso "ci-pipeline-key", origem fora do range de IPs do provedor de CI conhecido',
            "Volume elevado de chamadas de enumeracao de infraestrutura por credencial de CI a partir de origem anomala",
            "high", "ALTA", "T1580", 0,
            "chamadas massivas de enumeracao a partir de IP fora do range documentado do provedor de CI sugerem uso indevido da credencial de pipeline.",
        ),
        Caso(
            "Cloud", "10.0.4.200", "203.0.113.240", 443, "HTTPS",
            "conta de servico 'svc-etl-vendas' (uso historico restrito a bucket 'staging-vendas') executou GetObject em bucket 'prod-folha-pagamento' as 04:12, primeira ocorrencia registrada em 6 meses",
            "Conta de servico acessando bucket de dados sensiveis fora de seu escopo historico documentado",
            "medium", "ALTA", "T1078.004", 1,
            "contas de servico geram muito ruido de rotina e normalmente sao tratadas como baixo risco, mas o acesso a um bucket de folha de pagamento nunca antes tocado por essa credencial quebra o padrao de escopo documentado — contexto de desvio de escopo, nao o volume, e o que eleva a gravidade.",
        ),
        # --- MEDIA (12) ---
        Caso(
            "Cloud", "198.51.100.70", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"PutBucketPolicy","requestParameters":{"bucketName":"assets-publicos-site"},"userIdentity":{"arn":"...role/web-deploy"}} — bucket ja usado para servir assets estaticos publicos do site',
            "Alteracao de politica de bucket ja utilizado para servir conteudo publico do site institucional",
            "medium", "MEDIA", "T1530", 0,
            "bucket em questao ja hospeda conteudo publico por natureza, mas alteracao de politica fora do pipeline de deploy documentado merece confirmacao.",
        ),
        Caso(
            "Cloud", "192.0.2.155", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"ConsoleLogin","userIdentity":{"arn":"...user/joao.dev"},"responseElements":{"ConsoleLogin":"Success"},"additionalEventData":{"MFAUsed":"No"}}',
            "Login no console realizado sem MFA por usuario que normalmente utiliza autenticacao multifator",
            "medium", "MEDIA", "T1078.004", 0,
            "ausencia de MFA em login de usuario que costuma usa-lo e desvio de politica que requer confirmacao, mas origem geografica e horario sao normais.",
        ),
        Caso(
            "Cloud", "203.0.113.166", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"CreateAccessKey","userIdentity":{"arn":"...user/dev-staging"}} — segunda chave ativa criada para o mesmo usuario (politica recomenda apenas uma)',
            "Criacao de segunda chave de acesso ativa, excedendo recomendacao de boa pratica",
            "medium", "MEDIA", "T1552", 0,
            "excesso de chaves ativas e risco operacional relevante mas nao configura por si so evidencia de comprometimento.",
        ),
        Caso(
            "Cloud", "198.51.100.188", "0.0.0.0", 443, "HTTPS",
            'Azure Activity Log: usuario ana.torres autenticado de Lisboa, Portugal (usuario possui historico esporadico de viagens a trabalho registradas em sistema de RH, sem registro para esta data)',
            "Login de geografia incomum para o usuario, sem registro de viagem correspondente no periodo",
            "medium", "MEDIA", "T1078.004", 0,
            "geografia incomum sem confirmacao de viagem no sistema de RH e indicio moderado que exige contato com o usuario para validacao.",
        ),
        Caso(
            "Cloud", "192.0.2.170", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"ModifyDBInstance","requestParameters":{"publiclyAccessible":true},"resourceName":"rds-staging-01"}',
            "Instancia de banco de dados de staging alterada para acesso publico",
            "medium", "MEDIA", "T1530", 0,
            "exposicao publica de banco de dados e risco relevante mesmo em ambiente de staging, requer correcao e investigacao do motivo.",
        ),
        Caso(
            "Cloud", "203.0.113.180", "0.0.0.0", 443, "HTTPS",
            'GetSecretValue chamado 45 vezes em 2 minutos por role "lambda-processamento", acima da media historica de 3-5 chamadas por execucao',
            "Volume de chamadas a gerenciador de segredos acima do padrao historico da funcao",
            "medium", "MEDIA", "T1552", 0,
            "volume elevado pode indicar loop de erro na aplicacao ou tentativa de exfiltracao de segredos, requer analise de logs da funcao.",
        ),
        Caso(
            "Cloud", "198.51.100.199", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"DeleteTrail","requestParameters":{"name":"trilha-auditoria-secundaria"},"userIdentity":{"arn":"...user/infra-admin"}}',
            "Exclusao de trilha de auditoria secundaria (trilha principal permanece ativa)",
            "medium", "MEDIA", "T1098", 0,
            "exclusao de trilha de log e acao sensivel mesmo com trilha principal ativa, requer confirmacao de intencao com o administrador.",
        ),
        Caso(
            "Cloud", "192.0.2.205", "0.0.0.0", 443, "HTTPS",
            'chave de API do provedor de pagamento (modo teste, prefixo sk_test_) encontrada em log de aplicacao de staging exposto sem autenticacao',
            "Chave de API em modo de teste exposta em log de ambiente de staging",
            "medium", "MEDIA", "T1552", 0,
            "chave de modo teste tem impacto limitado, mas exposicao de log sem autenticacao e falha de configuracao que merece correcao e investigacao do escopo.",
        ),
        Caso(
            "Cloud", "203.0.113.215", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"AuthorizeSecurityGroupIngress","requestParameters":{"ipPermissions":{"fromPort":22,"toPort":22,"cidrIp":"0.0.0.0/0"}},"resourceName":"sg-ec2-dev"}',
            "Grupo de seguranca alterado para permitir SSH de qualquer origem na internet",
            "medium", "MEDIA", "T1580", 0,
            "abertura de porta administrativa para toda a internet e configuracao de risco elevado em ambiente de desenvolvimento, requer correcao.",
        ),
        Caso(
            "Cloud", "198.51.100.230", "0.0.0.0", 443, "HTTPS",
            'AWS GuardDuty finding: "Recon:IAMUser/MaliciousIPCaller.Custom" -- credencial "analytics-readonly" utilizada a partir de IP presente em lista de reputacao (Tor exit node)',
            "Credencial utilizada a partir de endereco IP conhecido como no de saida da rede Tor",
            "medium", "MEDIA", "T1078.004", 0,
            "uso a partir de infraestrutura de anonimizacao e sinal relevante de possivel comprometimento, mas a credencial e de escopo somente leitura, limitando o impacto imediato.",
        ),
        Caso(
            "Cloud", "192.0.2.240", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"PutBucketLifecycleConfiguration","requestParameters":{"bucketName":"logs-aplicacao","rules":[{"expiration":{"days":1}}]},"userIdentity":{"arn":"...user/devops-jr"}}',
            "Politica de ciclo de vida alterada para expirar logs de aplicacao em apenas 1 dia",
            "medium", "MEDIA", "", 0,
            "reducao drastica de retencao de logs pode ser erro de configuracao ou tentativa de ocultar rastros, requer confirmacao com o autor da mudanca.",
        ),
        Caso(
            "Cloud", "203.0.113.250", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"StopLogging","requestParameters":{"name":"trilha-principal"}} revertido automaticamente 40s depois por politica de auto-remediacao (Config Rule)',
            "Tentativa de interromper trilha de auditoria principal, revertida automaticamente por regra de conformidade",
            "medium", "MEDIA", "T1098", 0,
            "tentativa de desligar auditoria e sinal de alto risco mesmo com reversao automatica bem-sucedida, origem da chamada requer investigacao.",
        ),
        # --- BAIXA (8) ---
        Caso(
            "Cloud", "10.0.1.50", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"GetObject","requestParameters":{"bucketName":"docs-internos"},"userIdentity":{"arn":"...user/maria.souza"},"sourceIPAddress":"10.0.1.50"}',
            "Leitura de objeto em bucket interno por usuario autenticado a partir de rede corporativa",
            "low", "BAIXA", "", 0,
            "acesso de leitura simples, origem interna, usuario com permissao documentada, sem qualquer anomalia.",
        ),
        Caso(
            "Cloud", "10.0.1.60", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"DescribeInstances","userIdentity":{"arn":"...role/monitoring-readonly"}} chamado a cada 5 min pela ferramenta de monitoramento cadastrada',
            "Chamada de descricao de instancias por ferramenta de monitoramento em intervalo regular",
            "low", "BAIXA", "", 0,
            "role de somente leitura chamando API de descricao em intervalo regular e comportamento esperado de ferramenta de observabilidade.",
        ),
        Caso(
            "Cloud", "10.0.1.70", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"AssumeRole","requestParameters":{"roleArn":"arn:aws:iam::111122223333:role/deploy-ci"},"userIdentity":{"arn":"...user/github-actions"}}',
            "AssumeRole por identidade federada de pipeline de CI/CD conhecido",
            "low", "BAIXA", "", 0,
            "assuncao de role por identidade federada de pipeline documentado e padrao normal de deploy automatizado.",
        ),
        Caso(
            "Cloud", "10.0.1.80", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"CreateTags","requestParameters":{"resourceType":"instance","tags":[{"key":"Owner","value":"time-dados"}]}}',
            "Adicao de tag de metadados a instancia por engenheiro do proprio time responsavel",
            "low", "BAIXA", "", 0,
            "operacao trivial de marcacao de metadados sem qualquer implicacao de seguranca.",
        ),
        Caso(
            "Cloud", "10.0.1.90", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"ListBuckets","userIdentity":{"arn":"...user/ana.dev"}} chamada unica durante sessao normal de trabalho as 14:20',
            "Listagem simples de buckets durante sessao de trabalho em horario comercial",
            "low", "BAIXA", "", 0,
            "chamada isolada de listagem, horario comercial, sem sequencia de reconhecimento adicional.",
        ),
        Caso(
            "Cloud", "10.0.1.100", "0.0.0.0", 443, "HTTPS",
            "Azure Advisor: recomendacao gerada automaticamente sugerindo habilitar criptografia em repouso para disco gerenciado dev-disk-03",
            "Recomendacao automatica de boa pratica de seguranca gerada pela ferramenta de advisory da nuvem",
            "low", "BAIXA", "", 0,
            "recomendacao automatizada de melhoria, sem indicio de incidente ou exploracao em andamento.",
        ),
        Caso(
            "Cloud", "10.0.1.110", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"GetCostAndUsage","userIdentity":{"arn":"...user/financeiro-cloud"}} chamado no primeiro dia util do mes, padrao recorrente ha 18 meses',
            "Consulta de custos e uso da nuvem por usuario financeiro em rotina mensal recorrente",
            "low", "BAIXA", "", 0,
            "padrao recorrente e documentado de fechamento financeiro mensal, sem qualquer anomalia.",
        ),
        Caso(
            "Cloud", "10.0.1.120", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"UpdateFunctionCode","resourceName":"lambda-processa-pedidos","userIdentity":{"arn":"...user/dev-backend"}} via pipeline de deploy padrao',
            "Atualizacao de codigo de funcao serverless via pipeline de deploy documentado",
            "low", "BAIXA", "", 0,
            "deploy realizado via pipeline padrao da equipe, dentro do fluxo normal de desenvolvimento.",
        ),
        # --- FALSO_POSITIVO (10) ---
        Caso(
            "Cloud", "10.0.5.30", "0.0.0.0", 443, "HTTPS",
            'GitHub secret scanning alert: chave AWS AKIA_SANDBOX_TESTE123456 commitada em repositorio publico "empresa/exemplos-integracao", chave pertence a conta sandbox isolada sem acesso a recursos de producao (verificado via IAM boundary policy)',
            "Chave AWS de conta sandbox de testes, sem acesso a producao, commitada em repositorio de exemplos publico",
            "low", "FALSO_POSITIVO", "T1552", 1,
            "o formato da chave e identico a uma credencial real de producao (o que dispararia ALTA por padrao), mas trata-se de uma conta AWS sandbox isolada por policy de boundary, sem qualquer acesso a recursos de producao — o contexto da conta, nao o formato do achado, determina o rotulo baixo risco.",
        ),
        Caso(
            "Cloud", "10.0.5.31", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"PutBucketAcl","requestParameters":{"bucketName":"assets-cdn-publico","acl":"public-read"},"userIdentity":{"arn":"...role/cdn-deploy"}} — bucket documentado desde a criacao como origem de CDN publica',
            "Bucket configurado como publico corresponde a proposito documentado de servir CDN de assets estaticos",
            "low", "FALSO_POSITIVO", "T1530", 1,
            "PutBucketAcl com acl public-read e exatamente o evento que caracteriza o caso ALTA de exposicao de dados de clientes neste benchmark; apenas o proposito documentado do bucket (servir CDN publica de assets estaticos, nunca conteve dados sensiveis) distingue esta ocorrencia de um incidente real de exposicao.",
        ),
        Caso(
            "Cloud", "10.0.5.32", "0.0.0.0", 443, "HTTPS",
            'Azure AD Sign-in: usuario diretor.vendas autenticado de Singapura, viagem de negocios registrada e aprovada no sistema de RH para o periodo (ticket VIAGEM-2026-0442)',
            "Login de geografia incomum correspondente a viagem de negocios documentada e aprovada",
            "low", "FALSO_POSITIVO", "T1078.004", 1,
            "sem o registro de viagem, este seria um caso tipico de impossible travel/geografia anomala classificado como ALTA ou MEDIA; a confirmacao no sistema de RH com ticket de viagem aprovado resolve a ambiguidade a favor da legitimidade.",
        ),
        Caso(
            "Cloud", "10.0.5.33", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"AssumeRole","requestParameters":{"roleArn":"...role/security-audit-readonly"},"userIdentity":{"arn":"...user/auditor-externo"}} — sessao de auditoria de seguranca contratada, escopo limitado a leitura, aprovada em contrato AUD-2026-03',
            "AssumeRole de auditor externo contratado, escopo somente leitura, dentro de contrato de auditoria aprovado",
            "low", "FALSO_POSITIVO", "", 0,
            "acesso de auditor externo com escopo somente leitura e contrato formal de auditoria de seguranca em vigor.",
        ),
        Caso(
            "Cloud", "10.0.5.34", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"CreateAccessKey","userIdentity":{"arn":"...user/ci-rotation-bot"}} seguido por {"eventName":"DeleteAccessKey"} da chave anterior 3s depois — rotina automatizada de rotacao de chaves a cada 30 dias',
            "Rotina automatizada de rotacao de chave de acesso de conta de servico de CI",
            "low", "FALSO_POSITIVO", "T1552", 1,
            "CreateAccessKey isolado se assemelharia ao inicio da sequencia de persistencia maliciosa vista no caso ALTA deste benchmark (criar usuario, gerar chave, elevar privilegio); apenas a exclusao imediata da chave anterior no mesmo padrao de rotacao documentado de 30 dias resolve a favor de rotina legitima.",
        ),
        Caso(
            "Cloud", "10.0.5.35", "0.0.0.0", 443, "HTTPS",
            'AWS GuardDuty finding "Recon:IAMUser/MaliciousIPCaller.Custom" — IP correspondia a lista de reputacao desatualizada; validado manualmente como range legitimo do provedor de VPN corporativa contratado',
            "Alerta de reputacao de IP baseado em lista desatualizada, validado como range de VPN corporativa",
            "low", "FALSO_POSITIVO", "", 0,
            "investigacao manual confirmou que o IP pertence ao provedor de VPN corporativa contratado, lista de reputacao de terceiros estava desatualizada.",
        ),
        Caso(
            "Cloud", "10.0.5.36", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"AttachUserPolicy","requestParameters":{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"},"userIdentity":{"arn":"...user/infra-lead"}} — aprovado via workflow de change management CR-9077, dupla aprovacao registrada',
            "Concessao de acesso administrativo total seguindo processo formal de change management com dupla aprovacao",
            "high", "FALSO_POSITIVO", "T1098", 1,
            "a acao (anexar AdministratorAccess) e identica em forma a um escalonamento malicioso de privilegio, mas o processo de change management com dupla aprovacao documentada (CR-9077) confirma legitimidade — julgar apenas pela acao levaria a ALTA incorretamente.",
        ),
        Caso(
            "Cloud", "10.0.5.37", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"ModifyDBInstance","requestParameters":{"publiclyAccessible":false},"resourceName":"rds-prod-02"} — correcao aplicada pelo proprio time apos alerta anterior',
            "Correcao de exposicao publica de banco de dados aplicada pelo time responsavel apos alerta",
            "low", "FALSO_POSITIVO", "T1530", 0,
            "acao corretiva (tornando o recurso privado novamente) realizada pelo proprio time em resposta a um alerta anterior, remediacao concluida.",
        ),
        Caso(
            "Cloud", "10.0.5.38", "0.0.0.0", 443, "HTTPS",
            'GuardDuty finding suprimido automaticamente: "UnauthorizedAccess:EC2/SSHBruteForce" contra honeypot interno "decoy-ssh-01", instancia propositalmente exposta pela equipe de deteccao',
            "Tentativas de forca bruta SSH contra honeypot interno propositalmente exposto",
            "low", "FALSO_POSITIVO", "T1110", 1,
            "assinatura de forca bruta SSH e identica a de um ataque real contra um servidor de producao (severidade tipicamente ALTA); apenas o fato de o alvo ser um honeypot deliberadamente exposto pela propria equipe de deteccao torna as tentativas esperadas e nao indicativas de comprometimento real.",
        ),
        Caso(
            "Cloud", "10.0.5.39", "0.0.0.0", 443, "HTTPS",
            'CloudTrail: {"eventName":"GetSecretValue","userIdentity":{"arn":"...role/lambda-processamento"}} volume elevado explicado por pico sazonal de pedidos (Black Friday), correlacionado com aumento proporcional de invocacoes da funcao no mesmo periodo',
            "Volume elevado de chamadas a gerenciador de segredos correlacionado com pico sazonal legitimo de trafego",
            "low", "FALSO_POSITIVO", "T1552", 1,
            "o mesmo indicador (volume de GetSecretValue muito acima da media historica) aparece como caso MEDIA de possivel exfiltracao de segredos neste benchmark; apenas a correlacao proporcional com o pico sazonal conhecido de invocacoes da funcao explica o volume como trafego legitimo, nao exfiltracao.",
        ),
    ]
    assert len(casos) == 40, f"Cloud deve ter 40 casos, tem {len(casos)}"
    return casos
