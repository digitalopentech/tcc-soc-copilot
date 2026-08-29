"""Casos de telemetria Email GW (phishing, BEC, anexos, spoofing) para o benchmark.

40 alertas: 10 ALTA, 12 MEDIA, 8 BAIXA, 10 FALSO_POSITIVO — 8 ambiguos (20%).
"""

from __future__ import annotations


def casos_email() -> list:
    from gerar_benchmark import Caso

    casos = [
        # --- ALTA (10) ---
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: ceo@empresa-corp.com.br.security-verify.net | To: financeiro@empresa.com | Subject: URGENTE - Transferencia confidencial | Body: Preciso que voce faca uma TED de R$ 87.400,00 agora, estou em reuniao e nao posso ligar. Dados bancarios em anexo.",
            "BEC (Business Email Compromise) se passando por CEO solicitando transferencia urgente",
            "critical", "ALTA", "T1657", 0,
            "dominio spoofed do executivo, urgencia artificial e pedido de transferencia financeira sao assinatura classica de fraude BEC.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: security@paypa1-verify.com | Subject: Sua conta sera suspensa em 24h | Link: hxxp://paypa1-secure-login[.]tk/verify?id=8827 | anexo: fatura.html (formulario de credenciais embutido)",
            "Phishing com dominio tipossquatting e formulario de captura de credenciais em anexo HTML",
            "high", "ALTA", "T1598", 0,
            "dominio tipossquatting (paypa1 com numero 1) e anexo HTML com formulario de login sao tecnica confirmada de roubo de credenciais.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: rh@empresa.com (SPF: fail, DKIM: fail, envio real via 198.51.100.61) | Subject: Nova politica de ferias 2026.docm | anexo com macro VBA ofuscada detectada",
            "Falha de autenticacao SPF/DKIM combinada com anexo Office com macro maliciosa",
            "critical", "ALTA", "T1566", 0,
            "spoofing confirmado por falha simultanea de SPF e DKIM, com anexo carregando macro ofuscada — entrega ativa de malware.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: suporte-ti@empresa-corp.help | Subject: Redefinicao obrigatoria de senha | Link direciona para clone pixel-perfect do portal SSO corporativo hospedado em 203.0.113.199",
            "Pagina de login clonada do portal SSO corporativo para captura de credenciais",
            "high", "ALTA", "T1598", 0,
            "clone visual do portal SSO corporativo em dominio externo e ataque direcionado de coleta de credenciais corporativas.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: fornecedor.usual@parceiro-log.com (dominio legitimo comprometido, confirmado por CTI externa) | Subject: Fatura atualizada - novos dados bancarios | anexo: fatura_042026.pdf com QR code para novo PIX",
            "Comprometimento de conta de fornecedor real usada para fraude de alteracao de dados de pagamento",
            "critical", "ALTA", "T1657", 0,
            "conta legitima do fornecedor confirmada como comprometida por inteligencia externa, sendo usada para golpe de troca de dados bancarios (vendor email compromise).",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: notificacoes@empresa.com | regra de encaminhamento criada automaticamente na caixa de joana.reis apos login suspeito: encaminhar tudo contendo 'senha' OR 'contrato' para externo.leak@protonmail.com",
            "Regra de encaminhamento automatico criada apos comprometimento de conta para exfiltrar e-mails sensiveis",
            "critical", "ALTA", "T1114", 0,
            "regra de encaminhamento oculta filtrando por palavras-chave sensiveis para destino externo e tecnica confirmada de exfiltracao pos-comprometimento.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: diretoria@empresa.com.br-rh.info | Subject: Lista de demissoes confidencial - NAO COMPARTILHAR | anexo: lista.xlsm (macro habilitada, hash conhecido de familia Emotet)",
            "Isca de engenharia social sensivel (demissoes) entregando anexo com hash de malware conhecido",
            "critical", "ALTA", "T1566", 0,
            "hash do anexo corresponde a familia de malware conhecida (Emotet) e o pretexto emocional maximiza taxa de abertura.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: cobranca@energia-distribuidora.net | Subject: Fatura de energia vencida - corte em 48h | Link: hxxp://194.55.x.x/boleto.php (redireciona para exploit kit conhecido)",
            "Link malicioso redirecionando para exploit kit ativo identificado por feed de threat intelligence",
            "high", "ALTA", "T1566", 0,
            "redirecionamento confirmado para infraestrutura de exploit kit ativa, catalogada em feed de inteligencia de ameacas.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: presidencia@empresa.com (spoofed, IP de origem real: 192.0.2.140, sem correspondencia com servidores de email corporativos) | Subject: Aquisicao confidencial - preciso de vale-presentes Amazon $500x10 agora",
            "Golpe de vale-presentes (gift card scam) se passando pela presidencia",
            "high", "ALTA", "T1657", 0,
            "IP de origem nao corresponde a infraestrutura de email da empresa e o pedido de vale-presentes e padrao classico de fraude financeira via BEC.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: ana.paula.rh@empresa.com (conta interna real, DKIM valido, mas horario de envio 03:44 e destinatarios: 400 contas externas nunca contatadas antes)",
            "Conta interna legitima enviando volume massivo a destinatarios externos nunca antes contatados, horario atipico",
            "medium", "ALTA", "T1114", 1,
            "a autenticacao (DKIM/SPF) e valida, o que pareceria descartar phishing externo; mas o volume massivo, horario de madrugada e destinatarios inéditos indicam que a propria conta interna foi comprometida e esta sendo usada para disseminar phishing lateral — julgar so pela autenticidade tecnica do remetente levaria a subestimar o risco.",
        ),
        # --- MEDIA (12) ---
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: newsletter@banco-seguro-brasil.co (dominio similar a banco conhecido, sem .com.br) | Subject: Confirme seus dados | sem anexo, link para formulario simples",
            "Email com dominio similar a marca bancaria conhecida, link para formulario simples",
            "medium", "MEDIA", "T1598", 0,
            "similaridade de dominio e indicio de phishing, mas sem anexo malicioso ou confirmacao de captura de credenciais.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: rh@empresa.com (SPF: pass, DKIM: neutral) | Subject: Pesquisa de clima organizacional | Link para formulario Google Forms externo legitimo mas nao usual para RH",
            "Uso de servico externo nao usual (Google Forms) por area de RH para pesquisa interna",
            "medium", "MEDIA", "", 0,
            "autenticacao majoritariamente valida, mas ferramenta externa fora do padrao usual do departamento merece confirmacao.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: compras@fornecedor-novo.com.br | Subject: Proposta comercial | anexo: proposta.pdf (macro nao detectada, mas dominio registrado ha 5 dias)",
            "Anexo PDF sem macro de fornecedor com dominio recem-registrado",
            "medium", "MEDIA", "T1566", 0,
            "dominio muito recente e indicador de risco, mas anexo nao apresenta carga maliciosa confirmada na analise.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: ti-suporte@empresa.com | regra de encaminhamento criada por usuario para conta pessoal @gmail.com, sem filtro de palavra-chave, criada por acao manual do proprio usuario",
            "Regra de encaminhamento pessoal criada pelo proprio usuario para conta particular",
            "medium", "MEDIA", "T1114", 0,
            "encaminhamento para conta pessoal e violacao de politica de dados, mas parece ser configuracao deliberada do proprio usuario, nao indicio de conta comprometida.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: rh-beneficios@empresa-beneficios.com | Subject: Atualize seu cadastro do plano de saude | link para portal de terceiro conhecido (operadora real), certificado valido",
            "Comunicacao de beneficios direcionando a portal de operadora terceirizada legitima porem nao usual",
            "medium", "MEDIA", "", 0,
            "destino e legitimo (operadora de saude real) mas o padrao de comunicacao diverge do canal usual de RH, merece confirmacao.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: diretor.financeiro@empresa.com (SPF: fail) | Subject: Aprovar pagamento pendente | Body: sem pedido de valor especifico, apenas 'me liga quando puder'",
            "Falha de SPF em email do diretor financeiro, mas sem pedido concreto de transferencia",
            "medium", "MEDIA", "T1657", 0,
            "falha de autenticacao e sinal relevante de possivel spoofing, mas ausencia de pedido financeiro concreto reduz a urgencia imediata.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: eventos@empresa.com | Subject: Confraternizacao de fim de ano - confirme presenca | Link para Doodle poll externo (dominio legitimo, uso comum em outras areas)",
            "Link para ferramenta externa de agendamento em comunicacao de evento corporativo",
            "low", "MEDIA", "", 0,
            "ferramenta externa legitima e de uso comum na empresa, risco baixo mas fora do escopo tipico do gateway registrar apenas por precaucao.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: onboarding@sistema-rh-terceirizado.com | Subject: Complete seu cadastro de novo colaborador | anexo: formulario.xlsx com macro desabilitada por padrao mas presente",
            "Anexo com macro presente porem desabilitada por padrao, remetente de sistema terceirizado conhecido",
            "medium", "MEDIA", "T1566", 0,
            "presenca de macro no anexo e sinal relevante mesmo desabilitada por padrao, remetente e sistema terceirizado real mas requer confirmacao.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: alerta-seguranca@empresa.com (interno, SPF pass) | Subject: Seu acesso foi bloqueado, clique para desbloquear | link interno para portal legitimo, mas texto com urgencia atipica de campanha de phishing simulado",
            "Comunicacao interna com padrao textual de urgencia tipico de phishing, link para portal legitimo",
            "medium", "MEDIA", "T1598", 0,
            "estrutura textual identica a phishing pode ser campanha de conscientizacao (simulado) ou tentativa real; requer confirmacao com a equipe de seguranca antes de concluir.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: juridico@empresa.com (SPF pass, DKIM pass) | Subject: Notificacao judicial anexa | anexo: notificacao.zip protegido por senha (senha no corpo do email)",
            "Anexo compactado protegido por senha, tecnica comum tanto para confidencialidade legitima quanto para evadir scanners",
            "medium", "MEDIA", "T1566", 0,
            "zip com senha impede analise automatizada de conteudo; remetente autenticado reduz risco mas tecnica e tambem usada para evasao de deteccao.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: suporte@empresa.com | 15 usuarios reportaram o mesmo email como suspeito via botao 'Reportar Phishing' em 20 minutos",
            "Volume de denuncias de usuarios sobre o mesmo email em curto periodo",
            "medium", "MEDIA", "T1566", 0,
            "denuncias multiplas e sinal forte de campanha suspeita em andamento, mas ainda pendente de analise tecnica do conteudo do email.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: newsletter@parceiro-marketing.com | Subject: Baixe nosso novo e-book gratuito | link para landing page com muitos redirecionamentos em cadeia (5 saltos)",
            "Cadeia longa de redirecionamentos em email de marketing de parceiro conhecido",
            "medium", "MEDIA", "T1566", 0,
            "multiplos redirecionamentos sao tecnica comum tanto em marketing legitimo (tracking) quanto em evasao de filtros, requer verificacao do destino final.",
        ),
        # --- BAIXA (8) ---
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: contato@revista-tech.com.br | Subject: Newsletter semanal | link de descadastro padrao, remetente com historico de 2 anos sem reclamacoes",
            "Newsletter de assinatura legitima com historico consolidado",
            "low", "BAIXA", "", 0,
            "remetente com longo historico legitimo e conteudo tipico de newsletter, sem indicadores de phishing.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: no-reply@linkedin.com (SPF/DKIM/DMARC todos pass) | Subject: Voce tem 3 novas notificacoes",
            "Notificacao automatica de rede social profissional com autenticacao completa",
            "low", "BAIXA", "", 0,
            "todos os mecanismos de autenticacao de email (SPF, DKIM, DMARC) validados, conteudo padrao de notificacao.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: colega.interno@empresa.com | Subject: Duvida sobre planilha | anexo: planilha_vendas.xlsx sem macro, escaneado sem deteccoes",
            "Anexo de planilha entre colegas internos sem componentes ativos",
            "low", "BAIXA", "", 0,
            "comunicacao interna corriqueira, anexo sem macro ou script, sem indicadores de risco.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: no-reply@github.com (SPF/DKIM pass) | Subject: [org/repo] Novo pull request aberto",
            "Notificacao automatica de plataforma de desenvolvimento amplamente utilizada",
            "low", "BAIXA", "", 0,
            "notificacao automatizada de servico legitimo e conhecido pela equipe de desenvolvimento, autenticacao valida.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: diretor.regional@empresa.com (SPF pass, DKIM pass, IP de origem consistente com historico) | Subject: Aprovar compra de vale-presentes para premiacao de vendas | Body: comprar 20 vale-presentes de R$50 para a campanha trimestral de incentivo, processo ja aprovado em reuniao",
            "Pedido de compra de vale-presentes por diretor, autenticacao valida, referente a campanha de incentivo documentada",
            "low", "BAIXA", "T1657", 1,
            "pedido de vale-presentes e o mesmo padrao textual usado em golpes de gift card scam (ver caso ALTA de fraude similar neste benchmark), mas aqui a autenticacao e totalmente valida e o contexto (campanha trimestral de incentivo de vendas ja aprovada) e legitimo e rotineiro — julgar apenas pelo padrao textual 'vale-presentes' levaria a suspeita indevida.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: billing@aws.amazon.com (SPF/DKIM pass, dominio verificado) | Subject: Sua fatura mensal esta disponivel",
            "Fatura automatica de provedor de nuvem contratado com autenticacao valida",
            "low", "BAIXA", "", 0,
            "remetente e provedor de servico efetivamente contratado, autenticacao valida, conteudo esperado (fatura mensal).",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: rh@empresa.com (interno, SPF/DKIM pass) | Subject: Feliz aniversario! | mensagem automatica gerada pelo sistema de RH",
            "Mensagem automatica de aniversario gerada pelo sistema interno de RH",
            "low", "BAIXA", "", 0,
            "mensagem automatica de sistema interno conhecido, conteudo benigno, sem link ou anexo.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: suporte@ferramenta-projetos.com (SPF pass, ferramenta SaaS contratada pela empresa) | Subject: Manutencao programada neste sabado",
            "Aviso de manutencao de ferramenta SaaS contratada legitimamente pela empresa",
            "low", "BAIXA", "", 0,
            "comunicacao operacional padrao de fornecedor de software contratado, autenticacao valida, sem pedido de acao sensivel.",
        ),
        # --- FALSO_POSITIVO (10) ---
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: seguranca-conscientizacao@empresa.com | Subject: [SIMULACAO] Sua conta sera suspensa | payload textual identico a phishing real, tag oculta X-Phishing-Test: campanha-2026-Q2 no cabecalho",
            "Campanha interna de simulacao de phishing para treinamento de usuarios",
            "high", "FALSO_POSITIVO", "T1598", 1,
            "o corpo do email e estruturalmente identico a um phishing real (mesma urgencia, mesmo pretexto), mas o cabecalho X-Phishing-Test identifica a plataforma de simulacao contratada pela empresa — sem essa tag, o mesmo conteudo seria classificado como ALTA.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: no-reply@docusign.net (SPF/DKIM/DMARC pass) | Subject: Documento aguardando sua assinatura | link para docusign.net verificado",
            "Notificacao legitima de plataforma de assinatura eletronica contratada",
            "low", "FALSO_POSITIVO", "", 0,
            "dominio, autenticacao e servico correspondem exatamente ao provedor de assinatura eletronica contratado pela empresa.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: financeiro@empresa.com | mesmo pedido de TED enviado por engano 2x pelo proprio usuario em 3 minutos, confirmado por ligacao com o financeiro",
            "Email duplicado por engano do proprio remetente, confirmado por canal secundario",
            "low", "FALSO_POSITIVO", "", 0,
            "confirmacao por ligacao telefonica com o remetente real valida que o email e legitimo e apenas duplicado por erro.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: alertas@empresa.com | Subject: [TESTE INTERNO] verificacao de entrega de anexo EICAR | anexo: eicar.com (arquivo de teste padrao)",
            "Teste de entrega de anexo EICAR pela propria equipe de seguranca para validar o gateway",
            "medium", "FALSO_POSITIVO", "", 1,
            "a assinatura de deteccao de anexo malicioso e identica a de um malware real, mas o conteudo corresponde ao arquivo de teste padrao EICAR, enviado deliberadamente pela propria equipe interna para validar o gateway.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: ti-suporte@empresa.com (SPF pass, DKIM pass, dominio interno correto) | Subject: Redefinicao obrigatoria de senha - politica trimestral | link para portal SSO corporativo oficial (dominio empresa.com verificado)",
            "Comunicacao de redefinicao obrigatoria de senha por politica trimestral, autenticacao e dominio de destino legitimos",
            "low", "FALSO_POSITIVO", "T1598", 1,
            "o texto e a estrutura (redefinicao obrigatoria de senha, link de login) sao identicos a um dos casos ALTA de phishing deste benchmark, incluindo o mesmo pretexto de 'suporte-ti'; apenas a autenticacao completa (SPF/DKIM) e o dominio de destino genuinamente corporativo (nao um clone) confirmam que se trata da comunicacao trimestral legitima de politica de senhas.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: diretor.financeiro@empresa.com (SPF pass, DKIM pass) | Subject: Aprovar pagamento fornecedor XYZ R$ 12.400,00 | segue fluxo normal de aprovacao em duas etapas ja documentado",
            "Pedido de aprovacao de pagamento seguindo processo formal documentado de dupla checagem",
            "medium", "FALSO_POSITIVO", "T1657", 1,
            "o valor e o pedido de pagamento poderiam soar como BEC a primeira vista, mas o remetente e totalmente autenticado e o fluxo corresponde exatamente ao processo formal de aprovacao em duas etapas ja em vigor — descartar apenas pelo 'tom financeiro urgente' seria julgar mal um processo legitimo.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: recrutamento@empresa.com | regra de encaminhamento para vaga.recrutamento@agenciaparceira.com, criada manualmente pelo proprio recrutador para compartilhar triagem de curriculos, documentada em processo de RH",
            "Regra de encaminhamento para agencia de recrutamento parceira, processo documentado",
            "low", "FALSO_POSITIVO", "T1114", 1,
            "regra de encaminhamento automatico para dominio externo e o mesmo indicador tecnico usado no caso ALTA de exfiltracao pos-comprometimento deste benchmark; apenas o fato de ser criada manualmente pelo proprio usuario, sem filtro de palavras-chave sensiveis, e documentada em processo de RH distingue este caso de uma regra maliciosa.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: ti@empresa.com | Subject: [Simulado] Ganhe um iPhone respondendo a pesquisa | tag X-Phishing-Test: campanha-2026-Q1 no cabecalho, denunciado corretamente por 32 usuarios",
            "Segunda campanha de simulacao de phishing com alta taxa de denuncia correta pelos usuarios",
            "medium", "FALSO_POSITIVO", "T1598", 1,
            "isca de premio (iPhone) e link de pesquisa sao tecnica classica de phishing que resultaria em ALTA/MEDIA se real; a tag X-Phishing-Test no cabecalho e o unico elemento que confirma se tratar de simulacao interna de conscientizacao.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: financeiro@empresa.com (SPF pass, DKIM pass) | Subject: Atualizacao de dados bancarios do fornecedor XYZ | anexo: comprovante_alteracao.pdf | mudanca confirmada por ligacao telefonica ao contato cadastrado do fornecedor antes do processamento",
            "Solicitacao de alteracao de dados bancarios de fornecedor, confirmada por canal telefonico secundario antes de qualquer pagamento",
            "low", "FALSO_POSITIVO", "T1657", 1,
            "'atualizacao de dados bancarios de fornecedor' e exatamente o pretexto usado no caso ALTA de fraude de vendor email compromise deste benchmark; a diferenca decisiva e que aqui o processo de dupla checagem por telefone foi cumprido antes de qualquer transferencia, confirmando a legitimidade da solicitacao.",
        ),
        Caso(
            "Email GW", "0.0.0.0", "10.0.3.10", 25, "SMTP",
            "From: comunicacao@empresa.com | Subject: Simulado de resposta a incidentes - nao e um incidente real | exercicio de mesa (tabletop) anunciado previamente ao SOC pela equipe de continuidade de negocio",
            "Comunicacao sobre exercicio de simulacao de incidente, anunciado previamente",
            "low", "FALSO_POSITIVO", "", 0,
            "exercicio anunciado previamente pela equipe de continuidade de negocio, sem indicio de ameaca real.",
        ),
    ]
    assert len(casos) == 40, f"Email GW deve ter 40 casos, tem {len(casos)}"
    return casos
