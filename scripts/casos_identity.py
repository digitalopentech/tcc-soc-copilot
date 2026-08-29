"""Casos de telemetria Identity (autenticacao) para o benchmark.

40 alertas: 10 ALTA, 12 MEDIA, 8 BAIXA, 10 FALSO_POSITIVO — 8 ambiguos (20%).
"""

from __future__ import annotations


def casos_identity() -> list:
    from gerar_benchmark import Caso

    casos = [
        # --- ALTA (10) ---
        Caso(
            "Identity", "203.0.113.33", "10.0.1.20", 443, "TCP",
            "IdP log: usuario paula.matos autenticada de Sao Paulo (10.0.1.20 via VPN) as 09:14, e de Bucareste, Romenia (203.0.113.33) as 09:26 — 12 minutos de intervalo, deslocamento fisicamente impossivel",
            "Impossible travel confirmado entre duas autenticacoes da mesma conta",
            "critical", "ALTA", "T1078", 0,
            "distancia geografica e intervalo de tempo tornam o deslocamento fisico impossivel, confirmando comprometimento de credencial.",
        ),
        Caso(
            "Identity", "198.51.100.140", "10.0.1.20", 443, "TCP",
            "IdP log: 68 solicitacoes de push MFA enviadas para o dispositivo de ricardo.nunes entre 02:10 e 02:34, aprovada na 68a tentativa",
            "MFA fatigue: dezenas de solicitacoes push seguidas de aprovacao tardia de madrugada",
            "critical", "ALTA", "T1621", 0,
            "volume extremo de solicitacoes push em horario atipico seguido de aprovacao e assinatura classica de ataque de fadiga de MFA.",
        ),
        Caso(
            "Identity", "192.0.2.155", "10.0.1.20", 443, "TCP",
            "IdP log: 1 tentativa de senha 'Primavera2026!' testada contra 340 contas distintas em 5 minutos, origem unica 192.0.2.155",
            "Password spraying: senha unica testada contra centenas de contas diferentes",
            "high", "ALTA", "T1110.003", 0,
            "padrao classico de spray (poucas tentativas por conta, muitas contas) evade bloqueio por tentativas e indica ataque coordenado.",
        ),
        Caso(
            "Identity", "203.0.113.99", "10.0.1.30", 3389, "TCP",
            "IdP log: conta de servico 'svc-backup-db' (uso historico exclusivamente programatico via API) autenticada interativamente via RDP as 03:50 de IP externo 203.0.113.99",
            "Conta de servico usada de forma interativa via RDP a partir de origem externa",
            "critical", "ALTA", "T1078", 0,
            "contas de servico nao devem autenticar interativamente; uso via RDP de IP externo e forte indicio de credencial comprometida.",
        ),
        Caso(
            "Identity", "198.51.100.166", "10.0.1.20", 443, "TCP",
            "IdP log: usuario roberto.lima concluiu MFA via SMS apos numero ter sido portado (SIM swap) para novo dispositivo 6 horas antes, ticket de suporte de troca de numero nao localizado",
            "Autenticacao MFA por SMS apos troca de numero (SIM swap) sem ticket de suporte correspondente",
            "critical", "ALTA", "T1621", 0,
            "SIM swap sem registro formal de solicitacao de troca de numero e indicio forte de sequestro de conta via engenharia social com a operadora.",
        ),
        Caso(
            "Identity", "192.0.2.180", "10.0.1.20", 443, "TCP",
            "IdP log: usuario admin-global concedeu a si mesmo papel 'Global Administrator' as 04:02, revogando MFA obrigatorio para a propria conta em seguida",
            "Auto-concessao de privilegio administrativo global seguida de remocao do proprio requisito de MFA",
            "critical", "ALTA", "T1098", 0,
            "sequencia de auto-escalonamento e remocao de MFA propria e comportamento inequivocamente malicioso, mesmo vindo de conta com privilegio previo.",
        ),
        Caso(
            "Identity", "203.0.113.222", "10.0.1.20", 443, "TCP",
            "IdP log: token de sessao OAuth emitido para aplicativo de terceiros nao catalogado 'DocSync Pro' com escopo mail.read, contacts.read, files.readwrite.all para conta de diretor.financeiro",
            "Concessao de consentimento OAuth com escopo amplo a aplicativo de terceiros nao catalogado",
            "high", "ALTA", "T1114", 0,
            "escopo amplo (leitura de email e escrita em arquivos) concedido a app nao catalogado e vetor comum de exfiltracao de dados via consent phishing.",
        ),
        Caso(
            "Identity", "198.51.100.201", "10.0.1.20", 443, "TCP",
            "IdP log: usuario fernanda.costa autenticada com sucesso, porem de dispositivo nunca antes registrado, imediatamente seguida por consulta em massa ao diretorio (Get-MgUser -All, 4200 registros exportados)",
            "Login de dispositivo novo seguido imediatamente de exportacao massiva do diretorio de usuarios",
            "critical", "ALTA", "T1078", 0,
            "combinacao de dispositivo desconhecido e exportacao massiva de diretorio logo apos o login e padrao de reconhecimento pos-comprometimento.",
        ),
        Caso(
            "Identity", "192.0.2.230", "10.0.1.20", 443, "TCP",
            "IdP log: 5 contas de administrador tiveram o metodo de MFA alterado de aplicativo autenticador para SMS na mesma janela de 10 minutos, por 3 IPs de origem distintos e nunca antes vistos",
            "Downgrade coordenado de metodo de MFA em multiplas contas administrativas",
            "critical", "ALTA", "T1621", 0,
            "downgrade coordenado de MFA em varias contas privilegiadas simultaneamente e indicio de campanha ativa visando facilitar SIM swap subsequente.",
        ),
        Caso(
            "Identity", "10.0.4.150", "10.0.1.20", 443, "TCP",
            "IdP log: conta de servico 'svc-relatorios-bi' (padrao historico: login as 06:00 diariamente, unico IP interno fixo) autenticou 4 vezes adicionais fora do horario as 23:47, 00:12, 01:05 e 02:40, mesmo IP interno de sempre",
            "Conta de servico com autenticacoes extras fora do horario habitual, porem da mesma origem interna sempre utilizada",
            "medium", "ALTA", "T1078", 1,
            "a origem (mesmo IP interno de sempre) pareceria descartar risco, mas o padrao temporal quebrado (4 logins extras de madrugada, fora do agendamento unico diario documentado) sugere uso da credencial por um processo ou pessoa nao autorizados na mesma maquina — a origem familiar nao deve ser tomada como suficiente para descartar o caso.",
        ),
        # --- MEDIA (12) ---
        Caso(
            "Identity", "198.51.100.60", "10.0.1.20", 443, "TCP",
            "IdP log: usuario marcos.pereira autenticado de Lisboa 3 horas apos autenticacao em Sao Paulo — deslocamento fisicamente possivel por voo direto, mas sem viagem registrada em RH",
            "Geografia incomum com deslocamento fisicamente plausivel mas sem registro formal de viagem",
            "medium", "MEDIA", "T1078", 0,
            "diferente de impossible travel, o deslocamento e fisicamente viavel; a ausencia de registro de viagem e indicio moderado que exige confirmacao com o usuario.",
        ),
        Caso(
            "Identity", "192.0.2.90", "10.0.1.20", 443, "TCP",
            "IdP log: 6 solicitacoes de push MFA para o dispositivo de teresa.alves entre 08:45 e 08:52 (horario comercial), negadas todas, sem aprovacao",
            "Volume moderado de solicitacoes MFA negadas em horario comercial",
            "medium", "MEDIA", "T1621", 0,
            "volume moderado e negacao consistente sugerem tentativa nao bem-sucedida, mas requer contato com o usuario para confirmar origem.",
        ),
        Caso(
            "Identity", "198.51.100.63", "10.0.1.20", 443, "TCP",
            "IdP log: usuario helena.brito autenticada com sucesso a partir de navegador e sistema operacional nunca antes vistos para essa conta (fingerprint de dispositivo novo), mesma cidade e IP de faixa residencial conhecida do usuario",
            "Fingerprint de dispositivo/navegador completamente novo para a conta, porem geografia e faixa de IP compativeis com o padrao residencial do usuario",
            "medium", "MEDIA", "T1078", 0,
            "novo fingerprint de dispositivo e sinal moderado de possivel uso de maquina nao gerenciada ou navegador anonimo, mas a geografia consistente reduz a urgencia — requer confirmacao com o usuario antes de escalar.",
        ),
        Caso(
            "Identity", "203.0.113.110", "10.0.1.20", 443, "TCP",
            "IdP log: senha 'Empresa@123' testada contra 15 contas do departamento financeiro em 3 minutos, mesma origem",
            "Password spraying de escopo reduzido direcionado a um departamento especifico",
            "medium", "MEDIA", "T1110.003", 0,
            "volume menor de contas-alvo (15) que um spray massivo, mas direcionamento a departamento sensivel exige investigacao prioritaria.",
        ),
        Caso(
            "Identity", "198.51.100.175", "10.0.1.20", 443, "TCP",
            "IdP log: conta de servico 'svc-integracao-erp' autenticada de novo endereco IP interno (10.0.6.40) nunca antes utilizado, dentro do range corporativo",
            "Conta de servico autenticando de novo IP interno dentro do range corporativo esperado",
            "medium", "MEDIA", "T1078", 0,
            "novo IP esta dentro do range interno legitimo, reduzindo o risco, mas mudanca de padrao sem changelog associado merece confirmacao.",
        ),
        Caso(
            "Identity", "192.0.2.140", "10.0.1.20", 443, "TCP",
            "IdP log: token OAuth emitido para app catalogado 'Slack' com escopo adicional nao usual (files.readwrite.all) solicitado pela primeira vez",
            "Aplicativo catalogado solicitando escopo de permissao adicional nao usual",
            "medium", "MEDIA", "T1114", 0,
            "aplicativo e conhecido e catalogado, mas escopo adicional inedito requer validacao antes de ser tratado como rotina.",
        ),
        Caso(
            "Identity", "203.0.113.155", "10.0.1.20", 443, "TCP",
            "IdP log: usuario paulo.andrade tentou acessar aplicacao financeira sem permissao previa concedida (Access Denied), 3 tentativas em 2 minutos",
            "Tentativas repetidas de acesso a aplicacao sem autorizacao previa",
            "medium", "MEDIA", "T1078", 0,
            "tentativas negadas pelo proprio controle de acesso indicam que o controle funcionou, mas repeticao merece confirmacao da intencao do usuario.",
        ),
        Caso(
            "Identity", "198.51.100.210", "10.0.1.20", 443, "TCP",
            "IdP log: metodo de MFA de camila.rocha alterado de aplicativo autenticador para SMS, solicitado pelo proprio usuario via portal de autoatendimento, de dispositivo ja conhecido",
            "Downgrade de metodo de MFA solicitado via portal de autoatendimento por dispositivo conhecido",
            "medium", "MEDIA", "T1621", 0,
            "mudanca realizada por dispositivo ja reconhecido reduz o risco imediato, mas downgrade de MFA e sempre eventos sensiveis que exigem registro e acompanhamento.",
        ),
        Caso(
            "Identity", "192.0.2.199", "10.0.1.20", 443, "TCP",
            "IdP log: usuario bruno.tanaka executou Get-MgUser -All exportando 4200 registros do diretorio, primeira vez que esse usuario (analista de RH) executa esse comando",
            "Exportacao em massa de diretorio de usuarios por analista sem historico dessa acao",
            "medium", "MEDIA", "T1078", 0,
            "acao e tecnicamente compativel com atividades de RH (relatorio de headcount), mas ausencia de historico previo dessa acao especifica exige confirmacao do proposito.",
        ),
        Caso(
            "Identity", "203.0.113.177", "10.0.1.20", 443, "TCP",
            "IdP log: usuario daniela.freitas autenticada com sucesso 40 minutos apos 8 tentativas de senha incorreta, mesmo IP interno o tempo todo",
            "Multiplas tentativas de senha incorreta seguidas de sucesso, mesma origem interna",
            "medium", "MEDIA", "T1110", 0,
            "origem interna consistente reduz a probabilidade de ataque externo, mas volume de falhas antes do sucesso ainda merece registro e acompanhamento leve.",
        ),
        Caso(
            "Identity", "198.51.100.240", "10.0.1.20", 443, "TCP",
            "IdP log: conta 'svc-monitoramento-externo' (uso documentado apenas leitura de metricas) executou 3 chamadas de escrita (PATCH) em recurso de configuracao, fora do escopo tipico mas dentro de permissoes concedidas",
            "Conta de servico de monitoramento realizando operacoes de escrita dentro de suas permissoes mas fora do padrao de uso tipico",
            "medium", "MEDIA", "T1078", 0,
            "operacoes estao dentro das permissoes formalmente concedidas a conta, mas o desvio do padrao tipico de uso (somente leitura na pratica) merece esclarecimento com o time responsavel.",
        ),
        Caso(
            "Identity", "192.0.2.222", "10.0.1.20", 443, "TCP",
            "IdP log: usuario vitor.almeida com sessao ativa simultaneamente em 3 dispositivos de geografias distintas dentro do mesmo pais, sem indicio de impossible travel",
            "Multiplas sessoes ativas simultaneas em dispositivos e localidades distintas dentro do mesmo pais",
            "medium", "MEDIA", "T1078", 0,
            "sessoes simultaneas em localidades distintas porem dentro do mesmo pais e compativel tanto com uso legitimo multi-dispositivo quanto com compartilhamento indevido de credencial, requer confirmacao.",
        ),
        # --- BAIXA (8) ---
        Caso(
            "Identity", "10.0.1.200", "10.0.1.20", 443, "TCP",
            "IdP log: usuario leticia.souza autenticada de IP interno, 1 tentativa de senha incorreta seguida de sucesso imediato",
            "Falha de senha isolada seguida de sucesso, origem interna",
            "low", "BAIXA", "T1110", 0,
            "falha unica e provavel erro de digitacao, origem interna e sem qualquer outro indicador de risco.",
        ),
        Caso(
            "Identity", "10.0.1.210", "10.0.1.20", 443, "TCP",
            "IdP log: usuario gustavo.reis autenticado as 21:15 de IP interno, acessando sistema de chamados para resolver incidente fora do horario",
            "Acesso fora do horario comercial padrao por usuario interno em atividade de suporte",
            "low", "BAIXA", "", 0,
            "acesso fora de horario com proposito identificavel (suporte a incidente) e origem interna consistente e comportamento de baixo risco.",
        ),
        Caso(
            "Identity", "10.0.1.220", "10.0.1.20", 443, "TCP",
            "IdP log: 1 solicitacao de push MFA enviada e aprovada em 4 segundos por thiago.martins, dispositivo ja conhecido",
            "Unica solicitacao de MFA aprovada rapidamente por dispositivo ja reconhecido",
            "low", "BAIXA", "", 0,
            "solicitacao unica com aprovacao rapida e dispositivo conhecido e padrao normal de autenticacao, sem indicio de fadiga ou ataque.",
        ),
        Caso(
            "Identity", "10.0.1.230", "10.0.1.20", 443, "TCP",
            "IdP log: nova sessao de dispositivo movel registrada para camila.dias apos troca de aparelho, confirmada via SMS de codigo unico no mesmo numero cadastrado ha anos",
            "Registro de novo dispositivo confirmado via canal ja estabelecido de verificacao",
            "low", "BAIXA", "", 0,
            "novo dispositivo confirmado pelo mesmo canal de verificacao de longa data e fluxo normal de troca de aparelho.",
        ),
        Caso(
            "Identity", "10.0.1.240", "10.0.1.20", 443, "TCP",
            "IdP log: token OAuth renovado automaticamente para aplicativo interno ja catalogado 'Portal RH', sem alteracao de escopo",
            "Renovacao automatica de token para aplicativo interno ja catalogado sem mudanca de escopo",
            "low", "BAIXA", "", 0,
            "renovacao de token sem alteracao de escopo para aplicativo interno catalogado e operacao rotineira do ciclo de vida OAuth.",
        ),
        Caso(
            "Identity", "10.0.1.250", "10.0.1.20", 443, "TCP",
            "IdP log: usuario rafael.lima consultou proprio perfil e alterou numero de telefone de contato via portal de autoatendimento",
            "Autoatendimento de atualizacao de dados de contato pelo proprio usuario",
            "low", "BAIXA", "", 0,
            "acao trivial de autoatendimento sobre o proprio perfil, sem qualquer indicio de risco.",
        ),
        Caso(
            "Identity", "10.0.2.10", "10.0.1.20", 443, "TCP",
            "IdP log: conta de servico 'svc-relatorio-diario' autenticada as 06:00 em fim de semana, mesmo horario e origem de todos os dias uteis (job roda 7 dias por semana)",
            "Conta de servico autenticando em fim de semana no mesmo horario e origem habituais",
            "low", "BAIXA", "", 0,
            "job documentado para rodar todos os dias da semana, incluindo fins de semana, no mesmo horario e origem — sem anomalia real.",
        ),
        Caso(
            "Identity", "10.0.2.20", "10.0.1.20", 443, "TCP",
            "IdP log: usuario sandra.viana solicitou reset de senha via fluxo self-service, confirmado por e-mail corporativo e MFA",
            "Reset de senha via fluxo de autoatendimento com confirmacao dupla",
            "low", "BAIXA", "", 0,
            "fluxo padrao de reset de senha com dupla confirmacao (e-mail corporativo e MFA) e processo seguro e normal.",
        ),
        # --- FALSO_POSITIVO (10) ---
        Caso(
            "Identity", "10.0.5.50", "10.0.1.20", 443, "TCP",
            "IdP log: usuario felipe.moraes autenticado em Londres 5 horas apos autenticacao em Sao Paulo, viagem de negocios registrada e aprovada no sistema de RH (ticket VIAGEM-2026-0501), voo confirmado no itinerario corporativo",
            "Geografia incomum e intervalo curto explicados por viagem de negocios documentada com itinerario de voo confirmado",
            "low", "FALSO_POSITIVO", "T1078", 1,
            "o intervalo de 5 horas entre Sao Paulo e Londres se aproxima do limiar de impossible travel e seria tipicamente escalado como ALTA, mas o itinerario de voo confirmado no sistema de RH resolve inequivocamente a favor da legitimidade — o padrao temporal isolado enganaria a triagem automatica.",
        ),
        Caso(
            "Identity", "10.0.5.51", "10.0.1.20", 443, "TCP",
            "IdP log: 3 solicitacoes de push MFA para o dispositivo de eduardo.pinto entre 08:00 e 08:01, aprovada na primeira, usuario confirmou por chat que estava tentando logar em dois sistemas simultaneamente",
            "Multiplas solicitacoes MFA em curto intervalo explicadas por login simultaneo em dois sistemas pelo proprio usuario",
            "low", "FALSO_POSITIVO", "T1621", 0,
            "usuario confirmou via canal secundario (chat) que as solicitacoes correspondem a seu proprio comportamento de login simultaneo, nao a ataque de fadiga.",
        ),
        Caso(
            "Identity", "10.0.5.52", "10.0.1.20", 443, "TCP",
            "IdP log: senha padrao de onboarding testada contra 30 contas de estagiarios recem-criadas pelo proprio time de RH durante processo de integracao em lote, mesma origem do sistema de RH",
            "Teste de senha padrao contra lote de contas novas de estagiarios pelo proprio processo de onboarding de RH",
            "medium", "FALSO_POSITIVO", "T1110.003", 1,
            "o padrao (uma senha, muitas contas) e identico a um ataque de password spraying, mas a origem e o sistema de RH executando o processo formal e documentado de onboarding em lote de novos estagiarios — o mesmo padrao tecnico, sem esse contexto, seria classificado como ALTA.",
        ),
        Caso(
            "Identity", "10.0.5.53", "10.0.1.20", 443, "TCP",
            "IdP log: conta de servico 'svc-integracao-parceiro' autenticada de novo IP que corresponde exatamente ao anunciado pelo parceiro em aviso formal de mudanca de infraestrutura (email de aviso previo recebido pela equipe de integracao)",
            "Conta de servico autenticando de novo IP anunciado previamente pelo parceiro de integracao",
            "low", "FALSO_POSITIVO", "T1078", 1,
            "conta de servico autenticando de IP externo nunca antes visto e o mesmo indicador usado no caso ALTA de conta de servico comprometida deste benchmark; apenas a comunicacao formal previa do parceiro, correspondendo exatamente ao IP observado, resolve a favor de mudanca legitima de infraestrutura.",
        ),
        Caso(
            "Identity", "10.0.5.54", "10.0.1.20", 443, "TCP",
            "IdP log: token OAuth emitido para aplicativo 'Zoom' com escopo calendar.readwrite, aplicativo ja catalogado e aprovado pelo time de seguranca em revisao de fornecedores SAAS-2026",
            "Consentimento OAuth para aplicativo catalogado e formalmente aprovado pela seguranca",
            "low", "FALSO_POSITIVO", "", 0,
            "aplicativo consta na lista de fornecedores SaaS revisados e aprovados formalmente pelo time de seguranca.",
        ),
        Caso(
            "Identity", "10.0.5.55", "10.0.1.20", 443, "TCP",
            "IdP log: metodo de MFA de 4 administradores alterado simultaneamente de aplicativo para chave de seguranca fisica (FIDO2), executado pelo proprio time de seguranca como parte do projeto de hardening PROJ-MFA-2026",
            "Upgrade coordenado de metodo de autenticacao para chave fisica FIDO2 conduzido pelo proprio time de seguranca",
            "low", "FALSO_POSITIVO", "T1621", 1,
            "alteracao coordenada e simultanea do metodo de MFA em multiplas contas administrativas e o mesmo padrao do caso ALTA de downgrade malicioso deste benchmark; apenas a direcao da mudanca (upgrade para FIDO2, nao downgrade para SMS) e a autoria pelo proprio time de seguranca em projeto documentado distinguem os dois casos.",
        ),
        Caso(
            "Identity", "10.0.5.56", "10.0.1.20", 443, "TCP",
            "IdP log: usuario mariana.dutra exportou 4200 registros do diretorio via Get-MgUser -All, acao faz parte de relatorio trimestral de headcount documentado, aprovado pelo gestor de RH e recorrente ha 6 trimestres",
            "Exportacao em massa de diretorio correspondente a relatorio trimestral de RH documentado e recorrente",
            "low", "FALSO_POSITIVO", "T1078", 1,
            "exportacao de 4200 registros via Get-MgUser -All e o mesmo comando e volume do caso MEDIA de possivel reconhecimento pos-comprometimento deste benchmark; apenas a recorrencia documentada ao longo de 6 trimestres e a aprovacao formal do gestor de RH resolvem a favor de rotina legitima.",
        ),
        Caso(
            "Identity", "10.0.5.57", "10.0.1.20", 443, "TCP",
            "IdP log: 12 tentativas de login malsucedidas contra conta honeypot 'admin-decoy' criada deliberadamente pelo time de deteccao para capturar tecnicas de atacantes internos",
            "Tentativas de login contra conta honeypot deliberadamente exposta pelo time de deteccao",
            "low", "FALSO_POSITIVO", "T1110", 1,
            "12 tentativas malsucedidas contra uma conta 'admin' seguiria a regra padrao de escalar como forca bruta contra conta privilegiada; apenas o fato de a conta ser um honeypot deliberadamente criado pelo time de deteccao torna as tentativas esperadas e uteis, nao um incidente real.",
        ),
        Caso(
            "Identity", "10.0.5.58", "10.0.1.20", 443, "TCP",
            "IdP log: sessao simultanea de vinicius.rocha em notebook corporativo e celular pessoal cadastrado, mesma cidade, uso normal de aplicativo mobile de e-mail",
            "Sessoes simultaneas em dispositivos distintos porem cadastrados e na mesma localidade",
            "low", "FALSO_POSITIVO", "", 0,
            "ambos os dispositivos estao formalmente cadastrados pelo usuario e na mesma localidade, padrao esperado de uso multi-dispositivo.",
        ),
        Caso(
            "Identity", "10.0.5.59", "10.0.1.20", 443, "TCP",
            "IdP log: reset de senha em massa para 200 contas apos incidente de vazamento de senha em servico terceiro nao corporativo, forcado pelo proprio time de seguranca via script administrativo autorizado",
            "Reset de senha em massa executado pelo proprio time de seguranca como medida preventiva pos-vazamento externo",
            "low", "FALSO_POSITIVO", "", 1,
            "alteracao em massa de credenciais de 200 contas em curto intervalo se assemelharia a uma acao disruptiva de conta manipulation em larga escala; apenas a autoria do proprio time de seguranca, via script administrativo autorizado, e o contexto de resposta a um vazamento externo confirmado, resolvem a favor de medida preventiva legitima.",
        ),
    ]
    assert len(casos) == 40, f"Identity deve ter 40 casos, tem {len(casos)}"
    return casos
