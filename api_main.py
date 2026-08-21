"""
SOC Unified API — FastAPI
Combines: Alert ingestion, ML detection, Playbook generation, XAI/HITL,
SOAR execution, Gamification, Assets CRUD, and Incident management.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from config import config
from database import (
    Asset, GamificationMission, Incident, Playbook, PhishingReport,
    PhishingCampaign, PhishingTarget,
    SessionLocal, User, UserMission, get_db,
)
from gamification import gamification_engine, GamificationEngine
from ml_detection import ml_detector
from playbook_engine import playbook_engine
from scenario_data import CENARIOS, ATTACK_SCENARIOS
from soar_executor import soar_executor
from xai_hitl import hitl_manager, xai_explainer

app = FastAPI(
    title="MESI SOC API",
    description="Security Operations Center — API unificada",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ================================================================== #
# Pydantic schemas
# ================================================================== #

class AlertIn(BaseModel):
    type: str
    description: str
    severity: str = "MEDIA"
    source_ip: Optional[str] = None
    url: Optional[str] = None
    hash: Optional[str] = None
    port: Optional[int] = None
    asset_id: Optional[int] = None
    run_llm_pipeline: bool = False  # set True to trigger LLM agents


class AssetIn(BaseModel):
    name: str
    asset_type: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    owner: Optional[str] = None
    department: Optional[str] = None
    criticality: str = "MEDIO"
    os_system: Optional[str] = None
    location: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = []


class UserIn(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: str = "employee"
    department: Optional[str] = None


class HITLReviewIn(BaseModel):
    analyst_username: str
    decision: str       # VERDADEIRO_POSITIVO | FALSO_POSITIVO | ESCALAR
    notes: Optional[str] = ""


class PlaybookGenerateIn(BaseModel):
    incident_description: str
    threat_type: str
    severity: str = "ALTA"
    asset_context: Optional[str] = None


class MissionAnswerIn(BaseModel):
    user_id: int
    answers: List[int]


class ScenarioGenerateIn(BaseModel):
    incident_id: str
    incident_type: str
    severity: str
    description: Optional[str] = ""


class ScenarioRunIn(BaseModel):
    scenario_id: str


# ================================================================== #
# Health
# ================================================================== #


# ── Phishing Report schemas (modelo Cofense/PhishMe) ──
class PhishingReportIn(BaseModel):
    reporter_id: int
    sender: str
    subject: Optional[str] = ""
    body_snippet: Optional[str] = ""
    urls: List[str] = []
    has_attachment: bool = False


class ReportReviewIn(BaseModel):
    verdict: str            # malicious, simulated, benign
    is_simulation: bool = False
    reviewer_username: Optional[str] = None


# ── Phishing Simulation schemas (modelo Cofense/PhishMe) ──
class CampaignIn(BaseModel):
    name: Optional[str] = None
    template_type: str = "credential_harvest"
    target_user_ids: List[int] = []        # vazio = todos os colaboradores
    based_on_incident: Optional[str] = None


class OutcomeIn(BaseModel):
    user_id: int
    outcome: str                            # clicked, reported, ignored
    time_to_action_seconds: Optional[float] = None
    submitted_credentials: bool = False

@app.get("/health", tags=["Sistema"])
def health():
    return {
        "status": "online",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "modules": {
            "ml_detection": "L2 — Isolation Forest",
            "playbook_engine": "L3 — RAG + GPT-4o-mini",
            "xai_hitl": "L4 — XAI Explainer + HITL Queue",
            "soar": "L6 — SOAR Executor",
            "gamification": "L5 — Missions + Risk Score",
        },
    }


# ================================================================== #
# Alerts & Incidents (L1 → L6 pipeline)
# ================================================================== #

def _ingest_alert(alert: AlertIn, db: Session) -> Dict:
    """
    Ingest an alert and run the full pipeline:
    L2 ML detection → L3 Playbook → L4 XAI/HITL → L6 SOAR.
    Shared by /api/alerts and the scenario orchestrator (/api/scenarios/run).
    """
    incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
    alert_dict = alert.model_dump()

    # L2 — ML detection
    ml_score, is_anomaly, ml_explanation = ml_detector.detect(alert_dict)

    # L4 — XAI explanation
    xai_report = xai_explainer.explain(alert_dict, ml_explanation)

    # L3 — Playbook retrieval
    pb = playbook_engine.retrieve(f"{alert.type} {alert.description}", top_k=1)
    playbook_id = pb[0]["id"] if pb else None

    # L6 — SOAR actions
    soar_actions = soar_executor.plan(incident_id, alert.type, alert.severity)
    soar_results = soar_executor.execute(incident_id, soar_actions)

    # L4 — HITL queue if needed
    if xai_report.get("requires_hitl"):
        hitl_manager.request_review(incident_id, alert_dict, xai_report, ml_explanation)

    # Persist incident
    inc = Incident(
        incident_id=incident_id,
        title=f"{alert.type.title()} — {alert.severity}",
        description=alert.description,
        severity=alert.severity,
        status="investigating" if is_anomaly else "open",
        alert_data=alert_dict,
        ml_score=ml_score,
        ml_explanation=ml_explanation,
        playbook_id=playbook_id,
        soar_actions=soar_results,
        hitl_required=xai_report.get("requires_hitl", False),
    )
    db.add(inc)
    db.commit()
    db.refresh(inc)

    return {
        "incident_id": incident_id,
        "ml_score": round(ml_score, 4),
        "is_anomaly": is_anomaly,
        "xai_summary": xai_report.get("decision_summary"),
        "recommended_action": xai_report.get("recommended_action"),
        "playbook_id": playbook_id,
        "soar_actions_executed": len(soar_results),
        "hitl_required": xai_report.get("requires_hitl", False),
        "xai_report": xai_report,
        "ml_explanation": ml_explanation,
    }


@app.post("/api/alerts", tags=["Alertas"])
def submit_alert(alert: AlertIn, db: Session = Depends(get_db)):
    """
    Ingest an alert and run the full pipeline:
    L2 ML detection → L3 Playbook → L4 XAI/HITL → L6 SOAR.
    LLM agents (L3 triage) are optional (run_llm_pipeline=True).
    """
    return _ingest_alert(alert, db)


@app.get("/api/incidents", tags=["Incidentes"])
def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    q = db.query(Incident)
    if status:
        q = q.filter(Incident.status == status)
    if severity:
        q = q.filter(Incident.severity == severity)
    incidents = q.order_by(Incident.created_at.desc()).limit(limit).all()
    return [_incident_to_dict(i) for i in incidents]


@app.get("/api/incidents/{incident_id}", tags=["Incidentes"])
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(404, "Incidente não encontrado")
    return _incident_to_dict(inc)


@app.patch("/api/incidents/{incident_id}/status", tags=["Incidentes"])
def update_incident_status(
    incident_id: str,
    status: str,
    db: Session = Depends(get_db),
):
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(404, "Incidente não encontrado")
    inc.status = status
    if status == "resolved":
        inc.resolved_at = datetime.utcnow()
    db.commit()
    return {"incident_id": incident_id, "new_status": status}


# ================================================================== #
# Attack Scenarios — multi-incident demo orchestration
# ================================================================== #

# Tipo de incidente -> template de simulação de phishing mais adequado,
# usado para sugerir/lançar automaticamente uma campanha a partir de um cenário.
_SCENARIO_PHISHING_TEMPLATE = {
    "phishing": "credential_harvest",
    "account_compromise": "ceo_fraud",
}


def _scenario_summary(scn: Dict) -> Dict:
    incidents = [CENARIOS[i] for i in scn["incident_indices"]]
    return {
        "id": scn["id"],
        "name": scn["name"],
        "description": scn["description"],
        "incident_count": len(incidents),
        "threat_types": sorted({inc["type"] for inc in incidents}),
    }


@app.get("/api/scenarios", tags=["Cenários"])
def list_attack_scenarios():
    """Catálogo de cenários de ataque (grupos narrativos de incidentes) para demo."""
    return [_scenario_summary(s) for s in ATTACK_SCENARIOS]


@app.post("/api/scenarios/run", tags=["Cenários"])
def run_attack_scenario(req: ScenarioRunIn, db: Session = Depends(get_db)):
    """
    Lança um cenário de ataque: gera todos os incidentes do grupo através do
    pipeline L1→L6 normal, associa-lhes o playbook curado correto (em vez do
    match TF-IDF genérico), gera uma missão de formação gamificada por
    incidente, e sugere/lança uma campanha de phishing quando aplicável.
    """
    scn = next((s for s in ATTACK_SCENARIOS if s["id"] == req.scenario_id), None)
    if not scn:
        raise HTTPException(404, "Cenário não encontrado")

    incidents_out: List[Dict] = []
    playbooks_out: Dict[str, Dict] = {}
    missions_out: List[Dict] = []
    phishing_campaign_out: Optional[Dict] = None

    for idx in scn["incident_indices"]:
        tmpl = CENARIOS[idx]
        alert = AlertIn(
            type=tmpl["type"],
            description=tmpl["description"],
            severity=tmpl["severity"],
            source_ip=tmpl.get("source_ip"),
            url=tmpl.get("url"),
            hash=tmpl.get("hash"),
            port=tmpl.get("port"),
        )
        result = _ingest_alert(alert, db)

        # Substituir o match TF-IDF genérico pelo playbook curado deste cenário
        # (os 14 playbooks seeded cobrem os 12 tipos de ameaça; a RAG library
        # de retrieve() só conhece 7).
        curated_pb_id = tmpl.get("playbook")
        if curated_pb_id:
            pb_row = db.query(Playbook).filter(Playbook.playbook_id == curated_pb_id).first()
            if pb_row:
                inc_row = db.query(Incident).filter(
                    Incident.incident_id == result["incident_id"]
                ).first()
                inc_row.playbook_id = curated_pb_id
                pb_row.usage_count = (pb_row.usage_count or 0) + 1
                if not pb_row.source_incident:
                    pb_row.source_incident = result["incident_id"]
                db.commit()
                result["playbook_id"] = curated_pb_id
                if curated_pb_id not in playbooks_out:
                    playbooks_out[curated_pb_id] = _playbook_to_dict(pb_row)

        incidents_out.append({
            "incident_id": result["incident_id"],
            "type": tmpl["type"],
            "severity": tmpl["severity"],
            "ml_score": result["ml_score"],
            "hitl_required": result["hitl_required"],
            "playbook_id": result["playbook_id"],
        })

        # Gamificação: uma missão de formação gerada a partir deste incidente
        mission = gamification_engine.generate_from_incident({
            "incident_id": result["incident_id"],
            "type": tmpl["type"],
            "severity": tmpl["severity"],
            "description": tmpl["description"],
        })
        missions_out.append(mission)

        # Sugerir/lançar uma campanha de phishing (no máximo uma por cenário)
        if phishing_campaign_out is None and tmpl["type"] in _SCENARIO_PHISHING_TEMPLATE:
            tpl_key = _SCENARIO_PHISHING_TEMPLATE[tmpl["type"]]
            tpl = gamification_engine.get_sim_templates()[tpl_key]
            campaign_id = f"CMP-{datetime.now().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:6]}"
            campaign = PhishingCampaign(
                campaign_id=campaign_id,
                name=f"{tpl['name']} (baseada em {result['incident_id']})",
                template_type=tpl_key,
                difficulty=tpl["difficulty"],
                sender=tpl["sender"],
                subject=tpl["subject"],
                lure_url=tpl["lure_url"],
                teachable_moment=tpl["teachable_moment"],
                based_on_incident=result["incident_id"],
                status="active",
            )
            db.add(campaign)
            db.flush()
            employees = db.query(User).filter(User.role == "employee").all()
            for u in employees:
                db.add(PhishingTarget(
                    campaign_id=campaign.id, user_id=u.id,
                    username=u.username, department=u.department, outcome="pending",
                ))
            db.commit()
            phishing_campaign_out = {
                "campaign_id": campaign_id,
                "name": campaign.name,
                "template_type": tpl_key,
                "targets": len(employees),
                "based_on_incident": result["incident_id"],
            }

    return {
        "scenario_id": scn["id"],
        "scenario_name": scn["name"],
        "incidents": incidents_out,
        "playbooks": list(playbooks_out.values()),
        "training_missions": missions_out,
        "phishing_campaign": phishing_campaign_out,
    }


# ================================================================== #
# HITL Review (L4)
# ================================================================== #

@app.get("/api/hitl/pending", tags=["HITL"])
def get_pending_reviews():
    return hitl_manager.get_pending()


@app.get("/api/hitl/completed", tags=["HITL"])
def get_completed_reviews():
    return hitl_manager.get_completed()


@app.post("/api/hitl/{incident_id}/review", tags=["HITL"])
def submit_review(
    incident_id: str,
    review: HITLReviewIn,
    db: Session = Depends(get_db),
):
    result = hitl_manager.submit_review(
        incident_id, review.analyst_username, review.decision, review.notes or ""
    )
    if "error" in result:
        raise HTTPException(404, result["error"])

    # Update incident record
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if inc:
        inc.hitl_reviewed = True
        inc.reviewer_username = review.analyst_username
        inc.reviewer_decision = review.decision
        inc.reviewer_notes = review.notes
        inc.reviewed_at = datetime.utcnow()
        if review.decision == "VERDADEIRO_POSITIVO":
            inc.is_true_positive = True
        elif review.decision == "FALSO_POSITIVO":
            inc.is_true_positive = False
            inc.status = "closed"
        db.commit()

    return result


@app.get("/api/hitl/stats", tags=["HITL"])
def hitl_stats():
    return hitl_manager.stats()


# ================================================================== #
# Playbooks (L3)
# ================================================================== #

@app.get("/api/playbooks", tags=["Playbooks"])
def list_playbooks(db: Session = Depends(get_db)):
    pbs = db.query(Playbook).filter(Playbook.is_active == True).all()
    return [_playbook_to_dict(p) for p in pbs]


@app.get("/api/playbooks/library", tags=["Playbooks"])
def playbook_library():
    return playbook_engine.get_library()


@app.post("/api/playbooks/generate", tags=["Playbooks"])
def generate_playbook(req: PlaybookGenerateIn, db: Session = Depends(get_db)):
    pb_data = playbook_engine.generate(
        req.incident_description, req.threat_type, req.severity, req.asset_context
    )

    # Persist if generated
    if pb_data.get("generated"):
        pb = Playbook(
            playbook_id=pb_data.get("id", f"PB-GEN-{uuid.uuid4().hex[:8].upper()}"),
            name=pb_data.get("name", "Playbook Gerado"),
            threat_type=req.threat_type,
            severity_level=req.severity,
            steps=pb_data.get("steps", []),
            priority_actions=pb_data.get("priority_actions", []),
            is_generated=True,
        )
        db.add(pb)
        db.commit()

    return pb_data


@app.get("/api/playbooks/retrieve", tags=["Playbooks"])
def retrieve_playbook(query: str, top_k: int = 2):
    return playbook_engine.retrieve(query, top_k)


# ================================================================== #
# Assets
# ================================================================== #

@app.get("/api/assets", tags=["Ativos"])
def list_assets(
    department: Optional[str] = None,
    criticality: Optional[str] = None,
    asset_type: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(Asset).filter(Asset.is_active == True)
    if department:
        q = q.filter(Asset.department == department)
    if criticality:
        q = q.filter(Asset.criticality == criticality)
    if asset_type:
        q = q.filter(Asset.asset_type == asset_type)
    return [_asset_to_dict(a) for a in q.order_by(Asset.criticality.desc()).all()]


@app.post("/api/assets", tags=["Ativos"])
def create_asset(asset: AssetIn, db: Session = Depends(get_db)):
    a = Asset(**asset.model_dump())
    db.add(a)
    db.commit()
    db.refresh(a)
    return _asset_to_dict(a)


@app.get("/api/assets/{asset_id}", tags=["Ativos"])
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id, Asset.is_active == True).first()
    if not a:
        raise HTTPException(404, "Ativo não encontrado")
    return _asset_to_dict(a)


@app.put("/api/assets/{asset_id}", tags=["Ativos"])
def update_asset(asset_id: int, asset: AssetIn, db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Ativo não encontrado")
    for field, value in asset.model_dump().items():
        setattr(a, field, value)
    a.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(a)
    return _asset_to_dict(a)


@app.delete("/api/assets/{asset_id}", tags=["Ativos"])
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Ativo não encontrado")
    a.is_active = False
    db.commit()
    return {"deleted": asset_id}


# ================================================================== #
# Users
# ================================================================== #

@app.get("/api/users", tags=["Utilizadores"])
def list_users(role: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(User)
    if role:
        q = q.filter(User.role == role)
    return [_user_to_dict(u) for u in q.all()]


@app.post("/api/users", tags=["Utilizadores"])
def create_user(user: UserIn, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        raise HTTPException(400, "Username já existe")
    u = User(**user.model_dump())
    db.add(u)
    db.commit()
    db.refresh(u)
    return _user_to_dict(u)


@app.get("/api/users/{user_id}", tags=["Utilizadores"])
def get_user(user_id: int, db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "Utilizador não encontrado")
    return _user_to_dict(u)


# ================================================================== #
# Gamification (L5)
# ================================================================== #

@app.get("/api/gamification/scenarios", tags=["Gamificação"])
def list_scenarios(difficulty: Optional[str] = None):
    return gamification_engine.get_scenarios(difficulty)


@app.get("/api/gamification/scenarios/{scenario_id}", tags=["Gamificação"])
def get_scenario(scenario_id: str):
    sc = gamification_engine.get_scenario(scenario_id)
    if not sc:
        raise HTTPException(404, "Cenário não encontrado")
    return sc


@app.post("/api/gamification/scenarios/generate", tags=["Gamificação"])
def generate_scenario(req: ScenarioGenerateIn):
    incident_data = {
        "incident_id": req.incident_id,
        "type": req.incident_type,
        "severity": req.severity,
        "description": req.description,
    }
    return gamification_engine.generate_from_incident(incident_data)


@app.post("/api/gamification/scenarios/{scenario_id}/submit", tags=["Gamificação"])
def submit_mission(
    scenario_id: str,
    payload: MissionAnswerIn,
    db: Session = Depends(get_db),
):
    sc = gamification_engine.get_scenario(scenario_id)
    if not sc:
        raise HTTPException(404, "Cenário não encontrado")

    result = gamification_engine.evaluate_mission(payload.answers, sc)

    user = db.query(User).filter(User.id == payload.user_id).first()
    if not user:
        raise HTTPException(404, "Utilizador não encontrado")

    # Update user XP and stats
    user.xp_points = (user.xp_points or 0) + result["xp_earned"]
    user.total_missions = (user.total_missions or 0) + 1
    if result["passed"]:
        user.missions_completed = (user.missions_completed or 0) + 1
    user.level = GamificationEngine.calculate_level(user.xp_points)

    # Update risk score
    user.risk_score = GamificationEngine.update_risk_score(
        user.risk_score or 50.0,
        user.missions_completed,
        result["score_percentage"],
        False,
    )

    # Check new badges
    new_badges = gamification_engine.check_badges(
        _user_to_dict(user), result, elapsed_minutes=2.0
    )
    if new_badges:
        existing = list(user.badges or [])
        user.badges = existing + new_badges

    db.commit()

    return {
        **result,
        "new_badges": new_badges,
        "new_xp_total": user.xp_points,
        "new_level": user.level,
        "new_risk_score": user.risk_score,
    }


@app.post("/api/phishing/report", tags=["Phishing Report"])
def report_phishing(payload: PhishingReportIn, db: Session = Depends(get_db)):
    """
    Um colaborador reporta um email suspeito (botão de reporte estilo Cofense).
    O sistema faz triagem automática, recompensa o colaborador, e — se a ameaça
    for provável — cria telemetria/incidente no SOC. Fecha o ciclo L5 -> L1.
    """
    user = db.query(User).filter(User.id == payload.reporter_id).first()
    if not user:
        raise HTTPException(404, "Utilizador não encontrado")

    report_id = f"RPT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:6]}"
    report_dict = payload.model_dump()

    # Triagem automática (heurística) — prioriza, não substitui o analista
    triage = gamification_engine.triage_report(report_dict)

    # Recompensa de gamificação (reportar reduz o risco humano)
    reward = gamification_engine.reward_for_report(
        triage["verdict"], user.risk_score or 50.0
    )

    # Se a triagem indica ameaça provável, gera um incidente no SOC (L1 -> pipeline)
    linked_incident_id = None
    if triage["verdict"] == "malicious":
        linked_incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:6]}"
        inc = Incident(
            incident_id=linked_incident_id,
            title=f"Phishing reportado por colaborador — {payload.sender[:60]}",
            description=(payload.body_snippet or payload.subject or "")[:500],
            severity="MEDIA",
            status="open",
            alert_data={
                "type": "phishing",
                "source": "colaborador_report",
                "sender": payload.sender,
                "urls": payload.urls,
                "report_id": report_id,
                "triage_signals": triage["signals"],
            },
            ml_score=triage["threat_score"] / 100.0,
            hitl_required=triage["requires_soc_review"],
        )
        db.add(inc)

    # Persistir o reporte
    rpt = PhishingReport(
        report_id=report_id,
        reporter_id=user.id,
        reporter_username=user.username,
        sender=payload.sender,
        subject=payload.subject,
        body_snippet=payload.body_snippet,
        urls=payload.urls,
        has_attachment=payload.has_attachment,
        verdict=triage["verdict"],
        threat_score=triage["threat_score"],
        linked_incident_id=linked_incident_id,
        xp_awarded=reward["xp_awarded"],
        risk_reduction=reward["risk_reduction"],
    )
    db.add(rpt)

    # Atualizar o colaborador: XP, risco humano e medalhas
    user.xp_points = (user.xp_points or 0) + reward["xp_awarded"]
    user.level = GamificationEngine.calculate_level(user.xp_points)
    user.risk_score = reward["new_risk_score"]

    total_reports = db.query(PhishingReport).filter(
        PhishingReport.reporter_id == user.id
    ).count() + 1
    confirmed = db.query(PhishingReport).filter(
        PhishingReport.reporter_id == user.id,
        PhishingReport.verdict == "malicious",
    ).count()
    new_badges = gamification_engine.check_report_badges(
        _user_to_dict(user), total_reports, confirmed
    )
    if new_badges:
        user.badges = list(user.badges or []) + new_badges

    db.commit()

    return {
        "report_id": report_id,
        "triage": triage,
        "xp_awarded": reward["xp_awarded"],
        "risk_reduction": reward["risk_reduction"],
        "new_risk_score": user.risk_score,
        "new_xp_total": user.xp_points,
        "new_badges": new_badges,
        "incident_created": linked_incident_id,
        "message": (
            "Obrigado por reportar! Este email gerou um incidente no SOC."
            if linked_incident_id else
            "Obrigado por reportar! O SOC vai analisar o email."
        ),
    }


@app.get("/api/phishing/reports", tags=["Phishing Report"])
def list_phishing_reports(
    verdict: Optional[str] = None,
    reporter_id: Optional[int] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """Lista os reportes de phishing (fila de triagem para o analista SOC)."""
    q = db.query(PhishingReport)
    if verdict:
        q = q.filter(PhishingReport.verdict == verdict)
    if reporter_id:
        q = q.filter(PhishingReport.reporter_id == reporter_id)
    reports = q.order_by(PhishingReport.created_at.desc()).limit(limit).all()
    return [{
        "report_id": r.report_id,
        "reporter": r.reporter_username,
        "sender": r.sender,
        "subject": r.subject,
        "verdict": r.verdict,
        "threat_score": r.threat_score,
        "is_simulation": r.is_simulation,
        "linked_incident_id": r.linked_incident_id,
        "xp_awarded": r.xp_awarded,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    } for r in reports]


@app.patch("/api/phishing/reports/{report_id}/review", tags=["Phishing Report"])
def review_phishing_report(
    report_id: str, payload: ReportReviewIn, db: Session = Depends(get_db)
):
    """
    O analista SOC confirma o veredicto final de um reporte.
    Ajusta a recompensa do colaborador conforme a confirmação
    (ex.: apanhar uma simulação real do SOC é especialmente valorizado).
    """
    rpt = db.query(PhishingReport).filter(
        PhishingReport.report_id == report_id
    ).first()
    if not rpt:
        raise HTTPException(404, "Reporte não encontrado")

    rpt.verdict = payload.verdict
    rpt.is_simulation = payload.is_simulation
    rpt.reviewed_at = datetime.utcnow()

    # Reajustar recompensa face ao veredicto confirmado pelo analista
    user = db.query(User).filter(User.id == rpt.reporter_id).first()
    extra_xp = 0
    if user:
        target = "simulated" if payload.is_simulation else payload.verdict
        reward = gamification_engine.reward_for_report(target, user.risk_score or 50.0)
        extra_xp = max(0, reward["xp_awarded"] - (rpt.xp_awarded or 0))
        if extra_xp:
            user.xp_points = (user.xp_points or 0) + extra_xp
            user.level = GamificationEngine.calculate_level(user.xp_points)
        rpt.xp_awarded = (rpt.xp_awarded or 0) + extra_xp

    db.commit()
    return {
        "report_id": report_id,
        "confirmed_verdict": payload.verdict,
        "is_simulation": payload.is_simulation,
        "extra_xp_awarded": extra_xp,
    }


@app.post("/api/phishing/campaigns", tags=["Phishing Simulation"])
def launch_campaign(payload: CampaignIn, db: Session = Depends(get_db)):
    """
    Lança uma campanha de simulação de phishing (modelo Cofense/PhishMe).
    Seleciona os alvos e cria um registo por colaborador. Mede comportamento
    real: cada alvo poderá depois CLICAR, REPORTAR ou IGNORAR.
    """
    templates = gamification_engine.get_sim_templates()
    tpl = templates.get(payload.template_type)
    if not tpl:
        raise HTTPException(400, f"Template inválido. Opções: {list(templates)}")

    campaign_id = f"CMP-{datetime.now().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:6]}"
    campaign = PhishingCampaign(
        campaign_id=campaign_id,
        name=payload.name or tpl["name"],
        template_type=payload.template_type,
        difficulty=tpl["difficulty"],
        sender=tpl["sender"],
        subject=tpl["subject"],
        lure_url=tpl["lure_url"],
        teachable_moment=tpl["teachable_moment"],
        based_on_incident=payload.based_on_incident,
        status="active",
    )
    db.add(campaign)
    db.flush()  # obter o id

    # Selecionar alvos: especificados ou todos os colaboradores
    if payload.target_user_ids:
        targets = db.query(User).filter(User.id.in_(payload.target_user_ids)).all()
    else:
        targets = db.query(User).filter(User.role == "employee").all()

    for u in targets:
        db.add(PhishingTarget(
            campaign_id=campaign.id,
            user_id=u.id,
            username=u.username,
            department=u.department,
            outcome="pending",
        ))

    db.commit()
    return {
        "campaign_id": campaign_id,
        "name": campaign.name,
        "template_type": payload.template_type,
        "difficulty": tpl["difficulty"],
        "targets": len(targets),
        "status": "active",
        "message": f"Campanha lançada para {len(targets)} colaborador(es).",
    }


@app.post("/api/phishing/campaigns/{campaign_id}/outcome", tags=["Phishing Simulation"])
def record_outcome(campaign_id: str, payload: OutcomeIn, db: Session = Depends(get_db)):
    """
    Regista o comportamento real de um alvo: clicked / reported / ignored.
    Aplica o efeito de gamificação (XP e Human Risk Score) e devolve o
    momento formativo (teachable moment) se o colaborador clicou na isca.
    """
    if payload.outcome not in ("clicked", "reported", "ignored"):
        raise HTTPException(400, "outcome deve ser clicked, reported ou ignored")

    campaign = db.query(PhishingCampaign).filter(
        PhishingCampaign.campaign_id == campaign_id
    ).first()
    if not campaign:
        raise HTTPException(404, "Campanha não encontrada")

    target = db.query(PhishingTarget).filter(
        PhishingTarget.campaign_id == campaign.id,
        PhishingTarget.user_id == payload.user_id,
    ).first()
    if not target:
        raise HTTPException(404, "Colaborador não é alvo desta campanha")
    if target.outcome != "pending":
        raise HTTPException(409, f"Desfecho já registado: {target.outcome}")

    user = db.query(User).filter(User.id == payload.user_id).first()
    reward = gamification_engine.reward_for_outcome(payload.outcome, user.risk_score or 50.0)

    # Atualizar o alvo
    now = datetime.utcnow()
    target.outcome = payload.outcome
    target.action_at = now
    target.time_to_action_seconds = payload.time_to_action_seconds
    target.submitted_credentials = payload.submitted_credentials
    target.xp_delta = reward["xp_delta"]
    target.risk_delta = reward["risk_delta"]

    # Atualizar o colaborador
    user.xp_points = max(0, (user.xp_points or 0) + reward["xp_delta"])
    user.level = GamificationEngine.calculate_level(user.xp_points)
    user.risk_score = reward["new_risk_score"]
    db.commit()

    resp = {
        "campaign_id": campaign_id,
        "outcome": payload.outcome,
        "xp_delta": reward["xp_delta"],
        "risk_delta": reward["risk_delta"],
        "new_risk_score": user.risk_score,
        "new_xp_total": user.xp_points,
    }
    if reward["needs_teachable_moment"]:
        resp["teachable_moment"] = campaign.teachable_moment
    return resp


@app.get("/api/phishing/campaigns", tags=["Phishing Simulation"])
def list_campaigns(db: Session = Depends(get_db)):
    """Lista todas as campanhas com as suas métricas comportamentais."""
    out = []
    for c in db.query(PhishingCampaign).order_by(PhishingCampaign.created_at.desc()).all():
        targets = [{
            "outcome": t.outcome,
            "time_to_action_seconds": t.time_to_action_seconds,
        } for t in c.targets]
        out.append({
            "campaign_id": c.campaign_id,
            "name": c.name,
            "template_type": c.template_type,
            "difficulty": c.difficulty,
            "status": c.status,
            "metrics": gamification_engine.campaign_metrics(targets),
        })
    return out


@app.get("/api/phishing/campaigns/{campaign_id}", tags=["Phishing Simulation"])
def campaign_detail(campaign_id: str, db: Session = Depends(get_db)):
    """Detalhe de uma campanha: métricas + desfecho por colaborador."""
    c = db.query(PhishingCampaign).filter(
        PhishingCampaign.campaign_id == campaign_id
    ).first()
    if not c:
        raise HTTPException(404, "Campanha não encontrada")

    targets = [{
        "username": t.username,
        "department": t.department,
        "outcome": t.outcome,
        "time_to_action_seconds": t.time_to_action_seconds,
        "submitted_credentials": t.submitted_credentials,
    } for t in c.targets]

    return {
        "campaign_id": c.campaign_id,
        "name": c.name,
        "template_type": c.template_type,
        "difficulty": c.difficulty,
        "sender": c.sender,
        "subject": c.subject,
        "based_on_incident": c.based_on_incident,
        "status": c.status,
        "metrics": gamification_engine.campaign_metrics(
            [{"outcome": t["outcome"], "time_to_action_seconds": t["time_to_action_seconds"]}
             for t in targets]
        ),
        "targets": targets,
    }


@app.get("/api/gamification/leaderboard", tags=["Gamificação"])
def leaderboard(db: Session = Depends(get_db)):
    users = [_user_to_dict(u) for u in db.query(User).all()]
    return gamification_engine.leaderboard_from_users(users)


@app.get("/api/gamification/stats/{user_id}", tags=["Gamificação"])
def user_gamification_stats(user_id: int, db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "Utilizador não encontrado")
    d = _user_to_dict(u)
    d["level_progress"] = GamificationEngine.xp_to_next_level(u.xp_points or 0)
    return d


# ================================================================== #
# SOAR
# ================================================================== #

@app.get("/api/soar/log", tags=["SOAR"])
def soar_log(incident_id: Optional[str] = None):
    return soar_executor.get_log(incident_id)


@app.get("/api/soar/summary", tags=["SOAR"])
def soar_summary():
    return soar_executor.summary()


# ================================================================== #
# Analytics
# ================================================================== #

@app.get("/api/analytics/overview", tags=["Analytics"])
def analytics_overview(db: Session = Depends(get_db)):
    total = db.query(Incident).count()
    open_inc = db.query(Incident).filter(Incident.status == "open").count()
    investigating = db.query(Incident).filter(Incident.status == "investigating").count()
    resolved = db.query(Incident).filter(Incident.status == "resolved").count()
    true_pos = db.query(Incident).filter(Incident.is_true_positive == True).count()
    false_pos = db.query(Incident).filter(Incident.is_true_positive == False).count()

    assets_total = db.query(Asset).filter(Asset.is_active == True).count()
    users_total = db.query(User).count()
    missions_done = db.query(User).with_entities(
        User.missions_completed
    ).all()
    total_missions = sum(m[0] or 0 for m in missions_done)

    avg_risk = db.query(User).with_entities(User.risk_score).all()
    avg_risk_score = (
        round(sum(r[0] or 0 for r in avg_risk) / len(avg_risk), 1)
        if avg_risk else 0
    )

    return {
        "incidents": {
            "total": total,
            "open": open_inc,
            "investigating": investigating,
            "resolved": resolved,
            "true_positive": true_pos,
            "false_positive": false_pos,
        },
        "assets": {"total": assets_total},
        "users": {
            "total": users_total,
            "avg_risk_score": avg_risk_score,
            "total_missions_completed": total_missions,
        },
        "hitl": hitl_manager.stats(),
        "soar": soar_executor.summary(),
    }


# ================================================================== #
# Helper converters
# ================================================================== #

def _incident_to_dict(inc: Incident) -> Dict:
    return {
        "id": inc.id,
        "incident_id": inc.incident_id,
        "title": inc.title,
        "description": inc.description,
        "severity": inc.severity,
        "status": inc.status,
        "is_true_positive": inc.is_true_positive,
        "ml_score": inc.ml_score,
        "playbook_id": inc.playbook_id,
        "hitl_required": inc.hitl_required,
        "hitl_reviewed": inc.hitl_reviewed,
        "reviewer_decision": inc.reviewer_decision,
        "alert_data": inc.alert_data,
        "soar_actions": inc.soar_actions,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
    }


def _asset_to_dict(a: Asset) -> Dict:
    return {
        "id": a.id,
        "name": a.name,
        "asset_type": a.asset_type,
        "ip_address": a.ip_address,
        "mac_address": a.mac_address,
        "hostname": a.hostname,
        "owner": a.owner,
        "department": a.department,
        "criticality": a.criticality,
        "os_system": a.os_system,
        "location": a.location,
        "description": a.description,
        "tags": a.tags or [],
        "is_active": a.is_active,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


def _playbook_to_dict(p: Playbook) -> Dict:
    return {
        "id": p.id,
        "playbook_id": p.playbook_id,
        "name": p.name,
        "threat_type": p.threat_type,
        "severity_level": p.severity_level,
        "steps": p.steps or [],
        "priority_actions": p.priority_actions or [],
        "tags": p.tags or [],
        "is_generated": p.is_generated,
        "usage_count": p.usage_count,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }


def _user_to_dict(u: User) -> Dict:
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "full_name": u.full_name,
        "role": u.role,
        "department": u.department,
        "level": u.level or 1,
        "xp_points": u.xp_points or 0,
        "total_missions": u.total_missions or 0,
        "missions_completed": u.missions_completed or 0,
        "risk_score": u.risk_score or 50.0,
        "badges": u.badges or [],
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


# ================================================================== #
# Entry point
# ================================================================== #

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_main:app", host="0.0.0.0", port=config.WEBHOOK_PORT, reload=False)
