from sqlalchemy import (
    create_engine, Column, Integer, String, Float, DateTime,
    Text, Boolean, ForeignKey, JSON, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "soc_database.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    asset_type = Column(String(100))          # server, workstation, router, switch, firewall, iot
    ip_address = Column(String(50))
    mac_address = Column(String(50))
    hostname = Column(String(200))
    owner = Column(String(200))
    department = Column(String(100))
    criticality = Column(String(20))          # CRITICO, ALTO, MEDIO, BAIXO
    os_system = Column(String(100))
    location = Column(String(200))
    description = Column(Text)
    tags = Column(JSON, default=list)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(200))
    full_name = Column(String(200))
    role = Column(String(50))                 # soc_analyst, employee, manager, admin
    department = Column(String(100))
    level = Column(Integer, default=1)
    xp_points = Column(Integer, default=0)
    total_missions = Column(Integer, default=0)
    missions_completed = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)   # Human Risk Score (0-100)
    badges = Column(JSON, default=list)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)  # ativo associado ao utilizador
    created_at = Column(DateTime, default=datetime.utcnow)

    missions = relationship("UserMission", back_populates="user")
    asset = relationship("Asset", backref="users")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(100), unique=True, nullable=False)
    title = Column(String(300))
    description = Column(Text)
    severity = Column(String(20))             # CRITICA, ALTA, MEDIA, BAIXA
    status = Column(String(50), default="open")  # open, investigating, resolved, closed
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)  # ativo afetado
    is_true_positive = Column(Boolean, nullable=True)
    alert_data = Column(JSON)
    analysis_result = Column(Text)
    threat_assessment = Column(Text)
    playbook_id = Column(String(100))
    ml_score = Column(Float)
    ml_explanation = Column(JSON)
    soar_actions = Column(JSON, default=list)
    hitl_required = Column(Boolean, default=False)
    hitl_reviewed = Column(Boolean, default=False)
    reviewer_username = Column(String(100))
    reviewer_decision = Column(String(50))
    reviewer_notes = Column(Text)
    reviewed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime)

    asset = relationship("Asset", backref="incidents")


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(String(100), unique=True)
    name = Column(String(200), nullable=False)
    threat_type = Column(String(100))
    severity_level = Column(String(20))
    steps = Column(JSON, default=list)
    priority_actions = Column(JSON, default=list)
    tags = Column(JSON, default=list)
    is_generated = Column(Boolean, default=False)
    source_incident = Column(String(100))
    usage_count = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class GamificationMission(Base):
    __tablename__ = "gamification_missions"

    id = Column(Integer, primary_key=True, index=True)
    mission_id = Column(String(100), unique=True)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    scenario_type = Column(String(100))
    difficulty = Column(String(20))           # INICIANTE, INTERMEDIO, AVANCADO
    xp_reward = Column(Integer, default=50)
    based_on_incident = Column(String(100))
    scenario_data = Column(JSON)              # questions, options, answers
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user_missions = relationship("UserMission", back_populates="mission")


class UserMission(Base):
    __tablename__ = "user_missions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    mission_id = Column(Integer, ForeignKey("gamification_missions.id"))
    status = Column(String(20), default="pending")  # pending, in_progress, completed, failed
    score_percentage = Column(Float, default=0.0)
    xp_earned = Column(Integer, default=0)
    correct_answers = Column(Integer, default=0)
    total_questions = Column(Integer, default=0)
    answers = Column(JSON, default=list)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)

    user = relationship("User", back_populates="missions")
    mission = relationship("GamificationMission", back_populates="user_missions")


class TelemetryLog(Base):
    __tablename__ = "telemetry_logs"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(100))              # siem, firewall, endpoint, network, email
    event_type = Column(String(100))
    source_ip = Column(String(50))
    destination_ip = Column(String(50))
    raw_data = Column(JSON)
    ml_score = Column(Float)
    is_anomaly = Column(Boolean, default=False)
    processed = Column(Boolean, default=False)
    incident_id = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)


class PhishingReport(Base):
    """
    Reportes de emails suspeitos submetidos por colaboradores (modelo Cofense/PhishMe).
    Liga a camada L5 (colaborador) de volta à L1 (telemetria do SOCHAI),
    fechando o ciclo na direção colaborador -> SOCHAI.
    """
    __tablename__ = "phishing_reports"

    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(String(100), unique=True, nullable=False)
    reporter_id = Column(Integer, ForeignKey("users.id"))
    reporter_username = Column(String(100))

    # Conteúdo reportado pelo colaborador
    sender = Column(String(300))              # remetente do email suspeito
    subject = Column(String(500))
    body_snippet = Column(Text)               # excerto do corpo
    urls = Column(JSON, default=list)         # links presentes no email
    has_attachment = Column(Boolean, default=False)

    # Classificação atribuída pelo SOCHAI / triagem
    verdict = Column(String(30), default="pending")  # pending, malicious, simulated, benign
    is_simulation = Column(Boolean, default=False)    # era uma simulação de phishing do SOCHAI?
    threat_score = Column(Float, default=0.0)         # 0-100, atribuído na triagem
    linked_incident_id = Column(String(100))          # incidente gerado, se confirmado

    # Recompensa de gamificação
    xp_awarded = Column(Integer, default=0)
    risk_reduction = Column(Float, default=0.0)

    created_at = Column(DateTime, default=datetime.utcnow)
    reviewed_at = Column(DateTime)


class PhishingCampaign(Base):
    """
    Campanha de simulação de phishing lançada pelo SOCHAI (modelo Cofense/PhishMe).
    Mede comportamento real: cada alvo pode CLICAR, REPORTAR ou IGNORAR.
    """
    __tablename__ = "phishing_campaigns"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(String(100), unique=True, nullable=False)
    name = Column(String(200), nullable=False)
    template_type = Column(String(100))       # credential_harvest, fake_invoice, ceo_fraud, ...
    difficulty = Column(String(20))           # INICIANTE, INTERMEDIO, AVANCADO
    sender = Column(String(300))              # remetente simulado
    subject = Column(String(500))
    lure_url = Column(String(500))            # link-isca (sandbox/.test, nunca real)
    teachable_moment = Column(Text)           # mensagem formativa mostrada a quem clica
    based_on_incident = Column(String(100))   # incidente real que inspirou a campanha
    status = Column(String(20), default="active")  # active, closed
    created_at = Column(DateTime, default=datetime.utcnow)
    closed_at = Column(DateTime)

    targets = relationship("PhishingTarget", back_populates="campaign")


class PhishingTarget(Base):
    """
    Alvo individual de uma campanha de simulação.
    Regista o desfecho comportamental e o tempo até à ação.
    """
    __tablename__ = "phishing_targets"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("phishing_campaigns.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    username = Column(String(100))
    department = Column(String(100))

    # Desfecho comportamental: pending, clicked, reported, ignored
    outcome = Column(String(20), default="pending")
    sent_at = Column(DateTime, default=datetime.utcnow)
    action_at = Column(DateTime)
    time_to_action_seconds = Column(Float)
    submitted_credentials = Column(Boolean, default=False)  # caiu por completo?

    # Efeito de gamificação
    xp_delta = Column(Integer, default=0)
    risk_delta = Column(Float, default=0.0)

    campaign = relationship("PhishingCampaign", back_populates="targets")


class RiskEvent(Base):
    """Histórico do Human Risk Score: um registo por cada alteração do HRS de um colaborador."""
    __tablename__ = "risk_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    username = Column(String(100))
    event_type = Column(String(30))           # mission, phishing_sim, phishing_report
    detail = Column(String(200))              # cenário / desfecho
    difficulty = Column(String(20))
    score_percentage = Column(Float)          # só para missões
    risk_score = Column(Float)                # HRS após o evento
    risk_delta = Column(Float, default=0.0)
    xp_total = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


def create_tables():
    Base.metadata.create_all(bind=engine)


def run_migrations():
    """Migrações leves para bases de dados criadas antes de novas colunas.
    (SQLite `create_all` não altera tabelas existentes.)"""
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "incidents" not in inspector.get_table_names():
        return
    existing_cols = {c["name"] for c in inspector.get_columns("incidents")}
    if "asset_id" not in existing_cols:
        with engine.begin() as conn:
            conn.execute(text(
                "ALTER TABLE incidents ADD COLUMN asset_id INTEGER REFERENCES assets(id)"
            ))

    if "users" in inspector.get_table_names():
        existing_user_cols = {c["name"] for c in inspector.get_columns("users")}
        if "asset_id" not in existing_user_cols:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE users ADD COLUMN asset_id INTEGER REFERENCES assets(id)"
                ))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def seed_default_data():
    """Seed database with default playbooks and a demo user."""
    from sqlalchemy.orm import Session
    db: Session = SessionLocal()

    try:
        # Seed demo users if none exist
        if db.query(User).count() == 0:
            demo_users = [
                User(username="ana.silva", email="ana.silva@empresa.pt", full_name="Ana Silva",
                     role="soc_analyst", department="SOCHAI", level=3, xp_points=520),
                User(username="joao.costa", email="joao.costa@empresa.pt", full_name="João Costa",
                     role="employee", department="Financeiro", level=1, xp_points=80),
                User(username="maria.fernandes", email="maria.fernandes@empresa.pt",
                     full_name="Maria Fernandes", role="manager", department="TI", level=5, xp_points=1200),
                User(username="admin", email="admin@empresa.pt", full_name="Administrador SOCHAI",
                     role="admin", department="SOCHAI", level=8, xp_points=6000),
            ]
            db.add_all(demo_users)

        # Seed default assets if none exist
        if db.query(Asset).count() == 0:
            demo_assets = [
                Asset(name="Servidor Web Principal", asset_type="server", ip_address="192.168.1.10",
                      hostname="web-srv-01", department="TI", criticality="CRITICO",
                      os_system="Ubuntu 22.04 LTS", location="Datacenter A"),
                Asset(name="Firewall Perimetral", asset_type="firewall", ip_address="10.0.0.1",
                      hostname="fw-perimeter-01", department="TI", criticality="CRITICO",
                      os_system="FortiOS 7.4", location="Datacenter A"),
                Asset(name="Workstation RH-01", asset_type="workstation", ip_address="192.168.2.101",
                      hostname="ws-rh-01", owner="Ana Silva", department="RH",
                      criticality="MEDIO", os_system="Windows 11 Pro"),
                Asset(name="Switch Core", asset_type="switch", ip_address="192.168.1.1",
                      hostname="sw-core-01", department="TI", criticality="ALTO",
                      location="Datacenter A"),
                Asset(name="Servidor de Email", asset_type="server", ip_address="192.168.1.20",
                      hostname="mail-srv-01", department="TI", criticality="ALTO",
                      os_system="Windows Server 2022"),
            ]
            db.add_all(demo_assets)

        # Seed default playbooks (idempotent per playbook_id — adding new entries
        # to this list later doesn't require wiping an existing database)
        existing_pb_ids = {row[0] for row in db.query(Playbook.playbook_id).all()}
        all_pb_ids = {f"PB-{i:03d}" for i in range(1, 15)}
        if not all_pb_ids.issubset(existing_pb_ids):
            default_playbooks = [
                Playbook(
                    playbook_id="PB-001", name="Resposta a Malware", threat_type="malware",
                    severity_level="ALTA", tags=["malware", "virus", "trojan"],
                    steps=[
                        "1. Isolar o sistema afetado da rede imediatamente",
                        "2. Capturar imagem forense do sistema",
                        "3. Analisar IOCs com VirusTotal",
                        "4. Identificar o vetor de infeção inicial",
                        "5. Verificar outros sistemas potencialmente comprometidos",
                        "6. Erradicar o malware com ferramentas aprovadas",
                        "7. Restaurar a partir de backup limpo se necessário",
                        "8. Monitorar por 72 horas após remediação",
                        "9. Documentar e atualizar regras de deteção"
                    ],
                    priority_actions=["Isolar sistema", "Analisar IOCs", "Notificar equipa"]
                ),
                Playbook(
                    playbook_id="PB-002", name="Resposta a Phishing", threat_type="phishing",
                    severity_level="MEDIA", tags=["phishing", "email", "social engineering"],
                    steps=[
                        "1. Bloquear remetente e domínio no gateway de email",
                        "2. Identificar todos os utilizadores que receberam o email",
                        "3. Verificar cliques em links ou abertura de anexos",
                        "4. Remover email de todas as caixas afetadas",
                        "5. Analisar links e anexos em sandbox",
                        "6. Verificar comprometimento de credenciais",
                        "7. Forçar reset de passwords se necessário",
                        "8. Notificar utilizadores com orientações",
                        "9. Reportar ao serviço anti-abuso do domínio"
                    ],
                    priority_actions=["Bloquear domínio", "Identificar afetados", "Reset passwords"]
                ),
                Playbook(
                    playbook_id="PB-003", name="Resposta a Ransomware", threat_type="ransomware",
                    severity_level="CRITICA", tags=["ransomware", "encryption", "extortion"],
                    steps=[
                        "1. ISOLAR IMEDIATAMENTE todos os sistemas da rede",
                        "2. Desligar conexões para prevenir propagação",
                        "3. Identificar família de ransomware",
                        "4. Verificar disponibilidade de backups limpos",
                        "5. Contactar CERT nacional se necessário",
                        "6. NÃO pagar resgate sem autorização da direção",
                        "7. Recuperar a partir de backups verificados",
                        "8. Analisar vetor de infeção",
                        "9. Implementar proteções adicionais antes de reconectar"
                    ],
                    priority_actions=["ISOLAR REDE", "Verificar backups", "Contactar CERT"]
                ),
                Playbook(
                    playbook_id="PB-004", name="Resposta a Intrusão", threat_type="intrusion",
                    severity_level="ALTA", tags=["intrusion", "unauthorized access", "brute force"],
                    steps=[
                        "1. Bloquear IP de origem no firewall",
                        "2. Revogar todas as sessões ativas suspeitas",
                        "3. Analisar logs de autenticação",
                        "4. Verificar privilégios modificados",
                        "5. Analisar comandos executados",
                        "6. Identificar dados potencialmente exfiltrados",
                        "7. Reparar vulnerabilidades exploradas",
                        "8. Implementar MFA se não existente",
                        "9. Rever acessos e privilégios"
                    ],
                    priority_actions=["Bloquear IP", "Revogar sessões", "Analisar logs"]
                ),
                Playbook(
                    playbook_id="PB-005", name="Resposta a DDoS", threat_type="ddos",
                    severity_level="ALTA", tags=["ddos", "denial of service", "availability"],
                    steps=[
                        "1. Ativar proteção DDoS no ISP/CDN",
                        "2. Analisar tipo de ataque",
                        "3. Implementar rate limiting e blackholing",
                        "4. Ativar scrubbing center se disponível",
                        "5. Contactar ISP para filtros upstream",
                        "6. Manter serviços críticos via failover",
                        "7. Documentar o ataque em tempo real",
                        "8. Comunicar impactos aos stakeholders",
                        "9. Rever capacidades anti-DDoS após incidente"
                    ],
                    priority_actions=["Ativar DDoS protection", "Contactar ISP", "Failover"]
                ),
                Playbook(
                    playbook_id="PB-006", name="Exfiltração de Dados", threat_type="data_exfiltration",
                    severity_level="CRITICA", tags=["data breach", "sensitive data", "RGPD", "DLP"],
                    steps=[
                        "1. Identificar e bloquear canais de exfiltração (USB, cloud, email)",
                        "2. Determinar quais dados foram expostos e a sua classificação",
                        "3. Preservar evidências forenses com cadeia de custódia",
                        "4. Notificar DPO — avaliar se há dados pessoais (RGPD)",
                        "5. Se dados pessoais: notificar CNPD em ≤ 72 h (Art. 33 RGPD)",
                        "6. Suspender conta / revogar token cloud do utilizador envolvido",
                        "7. Comunicar aos titulares dos dados se risco elevado (Art. 34 RGPD)",
                        "8. Rever e ajustar políticas DLP e controlos de acesso (RBAC)",
                        "9. Lições aprendidas; documentar no registo de violações"
                    ],
                    priority_actions=["Bloquear canal exfiltração", "Notificar DPO", "Avaliar RGPD 72h"]
                ),
                # ── Playbooks adicionais (PDF INCIBE · 12 ameaças) ──────────
                Playbook(
                    playbook_id="PB-007", name="Fraude do CEO (BEC)", threat_type="account_compromise",
                    severity_level="CRITICA",
                    tags=["BEC", "CEO fraud", "wire transfer", "impersonation", "engenharia social"],
                    steps=[
                        "1. [HITL] Qualificar o pedido financeiro suspeito — congelar a ação de pagamento",
                        "2. [HITL] Verificar a transferência por canal alternativo (telefone direto conhecido)",
                        "3. Analisar mailbox do executivo: regras de reencaminhamento, logins recentes, forwarding",
                        "4. Verificar Reply-To ≠ From e domínio Levenshtein-próximo do corporativo",
                        "5. Se conta de executivo comprometida (ATO): reset de password + revogar sessões",
                        "6. Remover regras maliciosas da mailbox; purgar a mensagem (claw-back)",
                        "7. [HITL] Se transferência efetuada: contactar banco imediatamente para reverter",
                        "8. [HITL] Participação às FCSE (PSP/GNR) e notificação ao CERT.PT/INCIBE-CERT",
                        "9. Ativar banner de aviso em emails externos; reforçar DMARC enforcement"
                    ],
                    priority_actions=["Congelar pagamento", "Verificar por canal alternativo", "Analisar mailbox executivo"]
                ),
                Playbook(
                    playbook_id="PB-008", name="Fraude de RH (IBAN)", threat_type="account_compromise",
                    severity_level="ALTA",
                    tags=["HR fraud", "IBAN", "payroll", "impersonation", "engenharia social"],
                    steps=[
                        "1. Detetar/qualificar pedido de alteração de conta bancária (IBAN)",
                        "2. [HITL] Validar com o colaborador por canal alternativo (presencial ou telefone conhecido)",
                        "3. Bloquear alteração no sistema de RH/folha de pagamento até verificação",
                        "4. Analisar cabeçalhos do email: SPF/DKIM/DMARC, Reply-To, domínio remetente",
                        "5. Verificar se domínio remetente é look-alike (diferença de 1 carácter)",
                        "6. [HITL] Se IBAN já alterado e pagamento efetuado: contactar banco para reverter",
                        "7. [HITL] Participação às FCSE e notificação ao CERT.PT",
                        "8. Implementar workflow de aprovação dupla para alterações de dados bancários no RH",
                        "9. Restringir exposição pública de organograma e endereços de email"
                    ],
                    priority_actions=["Bloquear alteração IBAN", "Validar colaborador por canal alternativo", "Contactar banco"]
                ),
                Playbook(
                    playbook_id="PB-009", name="Sextorsão / Extorsão por Email", threat_type="other",
                    severity_level="MEDIA",
                    tags=["sextorsão", "extortion", "BTC", "spoofing", "breach"],
                    steps=[
                        "1. Confirmar que é campanha de sextorsão (sem IOC real de infeção no endpoint)",
                        "2. Purgar mensagens das caixas afetadas (claw-back automático)",
                        "3. Verificar se a password citada no email é real e ainda em uso (HaveIBeenPwned)",
                        "4. Se credencial ativa: forçar reset imediato de password + ativar MFA",
                        "5. Identificar outros colaboradores que receberam o mesmo template (carteira BTC igual)",
                        "6. Comunicar à equipa: não pagar, não responder, eliminar — o vídeo não existe",
                        "7. Reforçar SPF/DKIM/DMARC para impedir spoof do próprio domínio",
                        "8. [HITL] Notificar CERT.PT para mitigação da campanha"
                    ],
                    priority_actions=["Confirmar falso positivo de infeção", "Purgar emails", "Reset password se comprometida"]
                ),
                Playbook(
                    playbook_id="PB-010", name="Ataque à Página Web Corporativa", threat_type="intrusion",
                    severity_level="ALTA",
                    tags=["web attack", "OWASP", "defacement", "webshell", "SQLi", "WAF"],
                    steps=[
                        "1. Avaliar incidente: âmbito, tipologia, vetor (logs WAF/servidor/FIM)",
                        "2. [HITL] Comunicar a stakeholders; abrir incidente formal",
                        "3. Conter: colocar site em manutenção (maintenance mode) ou isolar servidor da rede",
                        "4. [HITL] Preservar provas: clonar disco, registar quem/quando com cadeia de custódia",
                        "5. Identificar e remover webshells ou ficheiros maliciosos (FIM diff)",
                        "6. Verificar base de dados: fugas de dados, alterações de conteúdo (defacement)",
                        "7. [HITL] Se dados pessoais expostos: notificar CNPD em ≤ 72h e CERT.PT",
                        "8. Recuperar: reinstalar CMS limpo, restaurar backup verificado, reparar vulnerabilidade",
                        "9. Pós-incidente: auditoria OWASP, atualizar CMS/plugins, WAF regras, MFA no backend"
                    ],
                    priority_actions=["Isolar servidor web", "Preservar evidências", "Notificar CNPD se dados expostos"]
                ),
                Playbook(
                    playbook_id="PB-011", name="Falso Suporte Técnico (Tech Support Scam)", threat_type="malware",
                    severity_level="ALTA",
                    tags=["tech support scam", "RMM", "AnyDesk", "TeamViewer", "Microsoft", "engenharia social"],
                    steps=[
                        "1. Confirmar instalação/execução não autorizada de ferramenta de acesso remoto (AnyDesk/TeamViewer)",
                        "2. Isolar equipamento da rede; terminar sessão remota imediatamente",
                        "3. Inventariar ações realizadas durante a sessão (comandos, ficheiros, credenciais acedidas)",
                        "4. Desinstalar software instalado após o contacto; limpar startup entries",
                        "5. [HITL] Mudar todas as credenciais dos serviços acedidos no equipamento durante a sessão",
                        "6. Verificar se houve operações bancárias — se sim, contactar banco imediatamente",
                        "7. Analisar com antimalware (scan completo); verificar persistência (scheduled tasks, registo)",
                        "8. [HITL] Reportar a FCSE, CERT.PT e ao Abuse da Microsoft (abuse@microsoft.com)",
                        "9. Formação: a Microsoft/Microsoft nunca contacta proativamente — desligar sempre"
                    ],
                    priority_actions=["Isolar e terminar sessão remota", "Mudar credenciais", "Scan antimalware completo"]
                ),
                Playbook(
                    playbook_id="PB-012", name="Email com Malware (Anexo/Link)", threat_type="malware",
                    severity_level="ALTA",
                    tags=["email malware", "macro", "VBA", "RAT", "keylogger", "sandbox"],
                    steps=[
                        "1. Triagem do email/alerta; extrair IOCs (URL, hash, remetente, anexo)",
                        "2. Detonar URL/anexo em sandbox; consultar VirusTotal/MetaDefender",
                        "3. Verificar execução no endpoint: cadeia de processos (Office → PowerShell/CMD/WScript)",
                        "4. Se execução confirmada: isolar host imediatamente",
                        "5. Purgar a campanha de todas as caixas (claw-back) e bloquear IOCs no mail gateway",
                        "6. Bloquear domínio/hash no proxy e EDR; atualizar regras SIEM",
                        "7. [HITL] Se dados pessoais em risco: notificar CNPD; reportar CERT.PT e FCSE",
                        "8. Bloquear macros de Internet por GPO; forçar Protected View no Office",
                        "9. Atualizar assinaturas antivírus e regras de deteção com novos IOCs"
                    ],
                    priority_actions=["Sandbox IOCs", "Verificar execução endpoint", "Purgar campanha email"]
                ),
                Playbook(
                    playbook_id="PB-013", name="Adware / Malvertising", threat_type="malware",
                    severity_level="MEDIA",
                    tags=["adware", "malvertising", "browser extension", "PUP", "drive-by"],
                    steps=[
                        "1. Detetar infeção de adware/malvertising no dispositivo (pop-ups, redirecionamentos)",
                        "2. Analisar extensões de browser instaladas — remover não autorizadas/recentes",
                        "3. Scan completo com antimalware; remover ficheiros detetados",
                        "4. Desinstalar software não autorizado (ordenar por data de instalação)",
                        "5. Limpar cache/histórico do browser; revogar permissões de sites suspeitos",
                        "6. Verificar alterações no ficheiro hosts e definições de proxy",
                        "7. Aplicar política de extensões aprovadas (allowlist via GPO/MDM)",
                        "8. Monitorar tráfego DNS do equipamento por 48h para detetar C2 residual",
                        "9. Formação: instalar software só de fontes oficiais; extensões mínimas e necessárias"
                    ],
                    priority_actions=["Remover extensões suspeitas", "Scan antimalware", "Rever política de software"]
                ),
                Playbook(
                    playbook_id="PB-014", name="Suplantação de Fornecedor (Fatura Falsa)", threat_type="other",
                    severity_level="CRITICA",
                    tags=["supplier fraud", "BEC", "IBAN", "invoice fraud", "impersonation"],
                    steps=[
                        "1. Detetar pedido suspeito de mudança de IBAN/fatura de fornecedor",
                        "2. [HITL] Verificar com o fornecedor por contacto CONHECIDO (telefone direto — nunca o do email)",
                        "3. Congelar pagamento/alteração no ERP até validação completa",
                        "4. Analisar cabeçalhos: domínio Levenshtein-próximo, Reply-To, SPF/DKIM/DMARC",
                        "5. Verificar se há thread hijacking (conversa legítima sequestrada pelo atacante)",
                        "6. [HITL] Se transferência já efetuada: contactar banco IMEDIATAMENTE para recall",
                        "7. [HITL] Participação às FCSE (PSP/GNR) com toda a documentação do caso",
                        "8. Notificar CERT.PT; atualizar lista de domínios look-alikes bloqueados",
                        "9. Implementar aprovação dupla para alterações de IBAN e faturas acima de limiar no ERP"
                    ],
                    priority_actions=["Congelar pagamento", "Verificar fornecedor por canal alternativo", "Contactar banco se transferido"]
                ),
            ]
            missing_playbooks = [pb for pb in default_playbooks if pb.playbook_id not in existing_pb_ids]
            if missing_playbooks:
                db.add_all(missing_playbooks)

        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Erro ao inicializar dados: {e}")
    finally:
        db.close()


# Initialize on import
create_tables()
run_migrations()
seed_default_data()
