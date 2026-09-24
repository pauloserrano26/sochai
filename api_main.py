"""
SOCHAI Unified API — FastAPI
Combines: Alert ingestion, ML detection, Playbook generation, XAI/HITL,
SOAR execution, Gamification, Assets CRUD, and Incident management.
"""

import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

import asset_threat_model
from config import config
from database import (
    Asset, AssetRelation, GamificationMission, Incident, Playbook, PhishingReport,
    PhishingCampaign, PhishingTarget, RiskEvent,
    SessionLocal, User, UserMission, get_db,
)
from gamification import gamification_engine, GamificationEngine
from ml_detection import get_ml_detector
from playbook_engine import playbook_engine
from scenario_data import CENARIOS, ATTACK_SCENARIOS
from soar_executor import soar_executor
from xai_hitl import hitl_manager, xai_explainer

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Aquece as camadas L2 e L3 no arranque.

    O detetor L2 importa o sklearn e treina a Isolation Forest na primeira
    utilização (~3 s). Feito aqui, esse custo deixa de cair no primeiro alerta
    submetido — que numa demonstração é precisamente o que se está a mostrar.
    """
    try:
        get_ml_detector().detect({
            "type": "scan",
            "description": "warm-up interno do detetor L2 (nenhum incidente criado)",
            "severity": "BAIXA",
        })
        playbook_engine.retrieve("warm-up", top_k=1)
        print("[SOCHAI] L2/L3 aquecidos — o primeiro alerta já não paga o arranque.")
    except Exception as exc:
        print(f"[AVISO] Warm-up L2/L3 falhou ({exc}) — o primeiro alerta será mais lento.")
    yield


app = FastAPI(
    title="MESI SOCHAI API",
    description="Security Operations Center — API unificada",
    version="2.0.0",
    lifespan=lifespan,
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
    services: Optional[List[Dict]] = []
    config: Optional[Dict] = {}


class AssetRelationIn(BaseModel):
    target_asset_id: int
    relation_type: str = "connected_to"
    protocol: Optional[str] = None
    port: Optional[int] = None
    network_zone: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = []


class UserIn(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: str = "employee"
    department: Optional[str] = None
    asset_id: Optional[int] = None


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


class AssetScenarioRunIn(BaseModel):
    """Cenário construído a partir das vulnerabilidades dos ativos reais."""
    asset_ids: List[int] = []           # vazio = os ativos mais vulneráveis do inventário
    max_incidents: int = 4
    max_per_asset: int = 2
    generate_playbooks: bool = True     # gerar playbook à medida (RAG + LLM) por vulnerabilidade
    launch_phishing: bool = True


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

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def _resolve_asset(alert_dict: Dict, db: Session) -> Optional[Asset]:
    """
    Associa a alerta a um ativo da empresa:
      1. asset_id explícito no payload;
      2. ativo cujo IP == source_ip da alerta;
      3. ativo cujo IP aparece na descrição ou URL (o mais crítico primeiro).
    Devolve None se nenhum ativo corresponder.
    """
    explicit = alert_dict.get("asset_id")
    if explicit:
        a = db.query(Asset).filter(Asset.id == explicit, Asset.is_active == True).first()
        if a:
            return a

    source_ip = (alert_dict.get("source_ip") or "").strip()
    if source_ip:
        a = (
            db.query(Asset)
            .filter(Asset.is_active == True, Asset.ip_address == source_ip)
            .first()
        )
        if a:
            return a

    text_ips = set()
    for field in ("description", "url"):
        value = alert_dict.get(field)
        if value:
            text_ips.update(_IPV4_RE.findall(value))
    text_ips.discard(source_ip)
    if text_ips:
        return (
            db.query(Asset)
            .filter(Asset.is_active == True, Asset.ip_address.in_(text_ips))
            .order_by(Asset.criticality.desc())
            .first()
        )
    return None


# Quantas missões de formação se geram ao mesmo tempo. Cada uma é uma chamada
# LLM independente e limitada por I/O; 8 em paralelo mantêm um cenário de 12
# incidentes em duas vagas sem atropelar o rate limit da API do modelo.
_MISSION_WORKERS = 8


def _resolve_pending_missions(pending: List[Dict]) -> List[Dict]:
    """
    Gera as missões de formação que ficaram pendentes de um ou mais incidentes.

    Gera **uma** missão por incidente, mesmo quando o ativo afetado tem vários
    donos — os restantes recebem uma cópia com o seu nome, sem custo adicional de
    LLM — e delega o lote em generate_from_incidents, que as gera em paralelo.
    """
    if not pending:
        return []

    by_incident: Dict[str, List[Dict]] = {}
    for item in pending:
        by_incident.setdefault(item["payload"]["incident_id"], []).append(item)

    groups = list(by_incident.values())
    missions = gamification_engine.generate_from_incidents(
        [group[0]["payload"] for group in groups], max_workers=_MISSION_WORKERS
    )

    out: List[Dict] = []
    for group, base in zip(groups, missions):
        for i, item in enumerate(group):
            if i == 0:
                mission = base
            else:
                # Cópia para o segundo dono do mesmo ativo: mesmo conteúdo,
                # identificador próprio, nenhuma chamada adicional ao modelo.
                mission = gamification_engine.add_scenario(
                    {k: v for k, v in base.items() if k != "id"}
                )
            mission["target_user_id"] = item.get("target_user_id")
            mission["target_username"] = item.get("target_username")
            mission["asset_id"] = item.get("asset_id")
            mission["asset_name"] = item.get("asset_name")
            if item.get("owner_entry") is not None:
                item["owner_entry"]["mission_id"] = mission["id"]
            out.append(mission)
    return out


def _ingest_alert(alert: AlertIn, db: Session, defer_missions: bool = False) -> Dict:
    """
    Ingest an alert and run the full pipeline:
    L2 ML detection → L3 Playbook → L4 XAI/HITL → L6 SOAR.
    Shared by /api/alerts and the scenario orchestrator (/api/scenarios/run).

    Com `defer_missions`, a geração das missões de formação (a única parte lenta
    do pipeline, por ser uma chamada LLM) não é feita aqui: sai em
    `_pending_missions` para quem chama a resolver de uma vez — em paralelo, ou
    em background — em vez de a somar incidente a incidente.
    """
    incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
    alert_dict = alert.model_dump()
    asset = _resolve_asset(alert_dict, db)

    # L2 — ML detection
    ml_score, is_anomaly, ml_explanation = get_ml_detector().detect(alert_dict)

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
        asset_id=asset.id if asset else None,
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

    # Reflete o incidente nos colaboradores associados ao ativo afetado:
    # sobe-lhes o risk score (sofreram um incidente de segurança real) e
    # gera uma missão de formação orientada a este incidente concreto —
    # é assim que um ativo fica "integrado" no SOC, e não apenas listado.
    affected_users: List[Dict] = []
    pending_missions: List[Dict] = []
    mission_payload = {
        "incident_id": incident_id,
        "type": alert.type,
        "severity": alert.severity,
        "description": alert.description,
    }
    if asset:
        owners = db.query(User).filter(User.asset_id == asset.id).all()
        for owner in owners:
            old_risk = owner.risk_score or 50.0
            owner.risk_score = GamificationEngine.update_risk_score(
                old_risk,
                owner.missions_completed or 0,
                0.0,
                True,
            )
            _log_risk_event(
                db, owner, "security_incident", incident_id, alert.severity, None, old_risk
            )
            entry = {
                "user_id": owner.id,
                "username": owner.username,
                "full_name": owner.full_name,
                "new_risk_score": owner.risk_score,
                "mission_id": None,
            }
            affected_users.append(entry)
            pending_missions.append({
                "payload": mission_payload,
                "owner_entry": entry,
                "target_user_id": owner.id,
                "target_username": owner.username,
                "asset_id": asset.id,
                "asset_name": asset.name,
            })
        if owners:
            db.commit()

    # O risco humano e o registo do evento são trabalho de base de dados e ficam
    # sempre feitos aqui; só a geração da missão é que pode ser diferida.
    if not defer_missions:
        _resolve_pending_missions(pending_missions)

    out = {
        "incident_id": incident_id,
        "ml_score": round(ml_score, 4),
        "is_anomaly": is_anomaly,
        "asset_id": asset.id if asset else None,
        "asset_name": asset.name if asset else None,
        "asset_criticality": asset.criticality if asset else None,
        "xai_summary": xai_report.get("decision_summary"),
        "recommended_action": xai_report.get("recommended_action"),
        "playbook_id": playbook_id,
        "soar_actions_executed": len(soar_results),
        "hitl_required": xai_report.get("requires_hitl", False),
        "xai_report": xai_report,
        "ml_explanation": ml_explanation,
        "affected_users": affected_users,
    }
    if defer_missions:
        out["_pending_missions"] = pending_missions
        out["missions_pending"] = len(pending_missions)
    return out


@app.post("/api/alerts", tags=["Alertas"])
def submit_alert(
    alert: AlertIn,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Ingest an alert and run the full pipeline:
    L2 ML detection → L3 Playbook → L4 XAI/HITL → L6 SOAR.
    LLM agents (L3 triage) are optional (run_llm_pipeline=True).

    A missão de formação dos donos do ativo afetado é gerada depois da resposta:
    é uma chamada LLM de alguns segundos que nada acrescenta ao resultado do
    pipeline, e assim o analista vê a triagem de imediato — a missão aparece na
    Gamificação quando estiver pronta.
    """
    result = _ingest_alert(alert, db, defer_missions=True)
    pending = result.pop("_pending_missions", [])
    if pending:
        background_tasks.add_task(_resolve_pending_missions, pending)
    return result


@app.get("/api/incidents", tags=["Incidentes"])
def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    asset_id: Optional[int] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    q = db.query(Incident)
    if status:
        q = q.filter(Incident.status == status)
    if severity:
        q = q.filter(Incident.severity == severity)
    if asset_id is not None:
        q = q.filter(Incident.asset_id == asset_id)
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


@app.patch("/api/incidents/{incident_id}/asset", tags=["Incidentes"])
def set_incident_asset(
    incident_id: str,
    asset_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """Associa (ou desassocia, com asset_id nulo) um incidente a um ativo."""
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(404, "Incidente não encontrado")
    if asset_id is not None:
        a = db.query(Asset).filter(Asset.id == asset_id, Asset.is_active == True).first()
        if not a:
            raise HTTPException(404, "Ativo não encontrado")
    inc.asset_id = asset_id
    db.commit()
    db.refresh(inc)
    return _incident_to_dict(inc)


# ================================================================== #
# Attack Scenarios — multi-incident demo orchestration
# ================================================================== #

# Tipo de incidente -> template de simulação de phishing mais adequado,
# usado para sugerir/lançar automaticamente uma campanha a partir de um cenário.
_SCENARIO_PHISHING_TEMPLATE = {
    "phishing": "credential_harvest",
    "account_compromise": "ceo_fraud",
}


def _launch_scenario_phishing(db: Session, tpl_key: str, incident_id: str) -> Dict:
    """
    Lança uma campanha de simulação de phishing inspirada num incidente do cenário,
    dirigida a todos os colaboradores. Partilhada pelos dois orquestradores de
    cenários (catálogo e ativos reais).
    """
    tpl = gamification_engine.get_sim_templates()[tpl_key]
    campaign_id = f"CMP-{datetime.now().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:6]}"
    campaign = PhishingCampaign(
        campaign_id=campaign_id,
        name=f"{tpl['name']} (baseada em {incident_id})",
        template_type=tpl_key,
        difficulty=tpl["difficulty"],
        sender=tpl["sender"],
        subject=tpl["subject"],
        lure_url=tpl["lure_url"],
        teachable_moment=tpl["teachable_moment"],
        based_on_incident=incident_id,
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
    return {
        "campaign_id": campaign_id,
        "name": campaign.name,
        "template_type": tpl_key,
        "targets": len(employees),
        "based_on_incident": incident_id,
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
    pending_missions: List[Dict] = []
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
        result = _ingest_alert(alert, db, defer_missions=True)
        incident_pending = result.pop("_pending_missions", [])

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
            "asset_id": result.get("asset_id"),
            "asset_name": result.get("asset_name"),
            "asset_criticality": result.get("asset_criticality"),
        })

        # L5 — uma única missão de formação por incidente. Quando o ativo
        # afetado tem dono, é a missão dirigida que o pipeline já pediu; quando
        # não tem, gera-se uma missão aberta. Antes pediam-se as duas, o que
        # duplicava a chamada LLM de cada incidente do cenário.
        if incident_pending:
            pending_missions.extend(incident_pending)
        else:
            pending_missions.append({
                "payload": {
                    "incident_id": result["incident_id"],
                    "type": tmpl["type"],
                    "severity": tmpl["severity"],
                    "description": tmpl["description"],
                },
                "owner_entry": None,
                "target_user_id": None,
                "target_username": None,
                "asset_id": result.get("asset_id"),
                "asset_name": result.get("asset_name"),
            })

        # Sugerir/lançar uma campanha de phishing (no máximo uma por cenário)
        if phishing_campaign_out is None and tmpl["type"] in _SCENARIO_PHISHING_TEMPLATE:
            phishing_campaign_out = _launch_scenario_phishing(
                db, _SCENARIO_PHISHING_TEMPLATE[tmpl["type"]], result["incident_id"]
            )

    # Todas as missões do cenário numa só vaga de chamadas concorrentes, em vez
    # de uma espera por incidente somada ao longo do ciclo acima.
    missions_out = _resolve_pending_missions(pending_missions)

    return {
        "scenario_id": scn["id"],
        "scenario_name": scn["name"],
        "incidents": incidents_out,
        "playbooks": list(playbooks_out.values()),
        "training_missions": missions_out,
        "phishing_campaign": phishing_campaign_out,
    }


# ================================================================== #
# Asset-driven scenarios — vulnerabilidades reais → incidentes →
# playbooks → gamificação
# ================================================================== #

def _resolve_scenario_playbook(
    db: Session,
    profile: Dict,
    vuln: Dict,
    incident_id: str,
    generate: bool,
) -> Dict:
    """
    Devolve o playbook de resposta para uma vulnerabilidade concreta.

    Com `generate`, pede ao motor L3 (RAG + LLM) um playbook à medida do ativo e
    da falha explorada, e persiste-o. Sem LLM disponível — ou se a geração
    falhar — cai no playbook curado da biblioteca para aquele tipo de ameaça.
    """
    threat_type = vuln["threat_type"]

    if generate and config.llm_available():
        pb_data = playbook_engine.generate(
            vuln["attack"],
            threat_type,
            vuln["severity"],
            asset_threat_model.asset_context(profile, vuln),
        )
        if pb_data.get("generated"):
            playbook_id = pb_data.get("id") or f"PB-GEN-{uuid.uuid4().hex[:8].upper()}"
            pb_row = Playbook(
                playbook_id=playbook_id,
                name=pb_data.get("name", f"Resposta — {vuln['title']}"),
                threat_type=threat_type,
                severity_level=vuln["severity"],
                steps=pb_data.get("steps", []),
                priority_actions=pb_data.get("priority_actions", []),
                tags=[vuln["id"], profile["asset_name"]],
                is_generated=True,
                source_incident=incident_id,
                usage_count=1,
            )
            db.add(pb_row)
            db.commit()
            db.refresh(pb_row)
            out = _playbook_to_dict(pb_row)
            out["estimated_time"] = pb_data.get("estimated_time")
            out["escalation_criteria"] = pb_data.get("escalation_criteria")
            return out

    # Playbook curado da biblioteca para este tipo de ameaça.
    pb_row = (
        db.query(Playbook)
        .filter(Playbook.is_active == True, Playbook.threat_type == threat_type)
        .order_by(Playbook.is_generated, Playbook.id)
        .first()
    )
    if pb_row:
        pb_row.usage_count = (pb_row.usage_count or 0) + 1
        db.commit()
        return _playbook_to_dict(pb_row)

    return {"playbook_id": None, "name": f"Sem playbook para «{threat_type}»", "steps": []}


@app.get("/api/scenarios/asset-risks", tags=["Cenários"])
def asset_risk_scan(
    asset_ids: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    Analisa o inventário real de ativos e devolve, por ativo, as vulnerabilidades
    deduzidas dos serviços expostos e da configuração de segurança registada.
    É a base do cenário gerado a partir dos ativos.
    """
    q = db.query(Asset).filter(Asset.is_active == True)
    if asset_ids:
        wanted = [int(x) for x in asset_ids.split(",") if x.strip().isdigit()]
        if wanted:
            q = q.filter(Asset.id.in_(wanted))

    assets = [_asset_to_dict(a) for a in q.all()]
    profiles = asset_threat_model.rank_profiles(
        [asset_threat_model.risk_profile(a) for a in assets]
    )
    vulnerable = [p for p in profiles if p["vulnerability_count"]]
    all_vulns = [v for p in vulnerable for v in p["vulnerabilities"]]

    return {
        "summary": {
            "assets_scanned": len(profiles),
            "assets_at_risk": len(vulnerable),
            "vulnerabilities_found": len(all_vulns),
            "critical_findings": sum(1 for v in all_vulns if v["severity"] == "CRITICA"),
            "threat_types": sorted({v["threat_type"] for v in all_vulns}),
            "avg_risk_score": (
                round(sum(p["risk_score"] for p in profiles) / len(profiles), 1)
                if profiles else 0.0
            ),
        },
        "assets": profiles,
    }


@app.post("/api/scenarios/from-assets", tags=["Cenários"])
def run_asset_scenario(req: AssetScenarioRunIn, db: Session = Depends(get_db)):
    """
    Gera um cenário/incidente a partir dos ativos que já existem no dashboard.

    Para cada vulnerabilidade encontrada no inventário cria o alerta realista que
    a sua exploração produziria, passa-o pelo pipeline L1→L6, gera o playbook de
    resposta correspondente e, em consequência, a missão de formação e o impacto
    no risco humano dos colaboradores donos do ativo afetado.
    """
    q = db.query(Asset).filter(Asset.is_active == True)
    if req.asset_ids:
        q = q.filter(Asset.id.in_(req.asset_ids))
    assets = [_asset_to_dict(a) for a in q.all()]
    if not assets:
        raise HTTPException(404, "Nenhum ativo ativo encontrado para analisar")

    profiles = asset_threat_model.rank_profiles(
        [asset_threat_model.risk_profile(a) for a in assets]
    )
    path = asset_threat_model.select_attack_path(
        profiles, max(1, req.max_incidents), max(1, req.max_per_asset)
    )
    if not path:
        raise HTTPException(
            400,
            "Os ativos selecionados não apresentam vulnerabilidades — "
            "não há cenário para gerar. Escolha outros ativos ou registe "
            "serviços/configuração de segurança no inventário.",
        )

    incidents_out: List[Dict] = []
    playbooks_out: Dict[str, Dict] = {}
    missions_out: List[Dict] = []
    affected_users: Dict[int, Dict] = {}
    phishing_campaign_out: Optional[Dict] = None
    scenario_id = f"ASSET-SCN-{datetime.now().strftime('%Y%m%d%H%M%S')}"

    for step in path:
        profile, vuln = step["profile"], step["vulnerability"]

        # L1 → L6: o alerta entra pelo mesmo pipeline dos alertas reais e já
        # traz o asset_id, pelo que arrasta o dono do ativo para a camada L5.
        result = _ingest_alert(AlertIn(**asset_threat_model.build_alert(profile, vuln)), db)
        incident_id = result["incident_id"]

        # L3 — playbook para esta vulnerabilidade concreta.
        pb = _resolve_scenario_playbook(db, profile, vuln, incident_id, req.generate_playbooks)
        if pb.get("playbook_id"):
            inc_row = db.query(Incident).filter(Incident.incident_id == incident_id).first()
            inc_row.playbook_id = pb["playbook_id"]
            db.commit()
            result["playbook_id"] = pb["playbook_id"]
            entry = playbooks_out.setdefault(pb["playbook_id"], {**pb, "vulnerabilities": []})
            entry["vulnerabilities"].append({
                "title": vuln["title"],
                "asset_name": profile["asset_name"],
                "evidence": vuln["evidence"],
                "remediation": vuln["remediation"],
            })

        incidents_out.append({
            "incident_id": incident_id,
            "type": vuln["threat_type"],
            "severity": vuln["severity"],
            "ml_score": result["ml_score"],
            "hitl_required": result["hitl_required"],
            "playbook_id": result["playbook_id"],
            "asset_id": profile["asset_id"],
            "asset_name": profile["asset_name"],
            "asset_criticality": profile["criticality"],
            "vulnerability": vuln["title"],
            "vulnerability_id": vuln["id"],
            "evidence": vuln["evidence"],
            "remediation": vuln["remediation"],
            "description": vuln["attack"],
        })

        # L5 — gamificação. O pipeline já gerou uma missão dirigida a cada dono
        # do ativo; se o ativo não tiver dono registado, gera-se uma missão
        # aberta para que a fragilidade seja na mesma trabalhada em formação.
        incident_missions = [
            gamification_engine.get_scenario(u["mission_id"])
            for u in result.get("affected_users", [])
        ]
        incident_missions = [m for m in incident_missions if m]
        if not incident_missions:
            mission = gamification_engine.generate_from_incident({
                "incident_id": incident_id,
                "type": vuln["threat_type"],
                "severity": vuln["severity"],
                "description": vuln["attack"],
            })
            mission["asset_id"] = profile["asset_id"]
            mission["asset_name"] = profile["asset_name"]
            incident_missions = [mission]

        for mission in incident_missions:
            mission["vulnerability"] = vuln["title"]
            missions_out.append(mission)

        for u in result.get("affected_users", []):
            affected_users[u["user_id"]] = {
                **u,
                "asset_name": profile["asset_name"],
                "vulnerability": vuln["title"],
            }

        # Simulação de phishing quando a fragilidade é do domínio humano.
        if (
            req.launch_phishing
            and phishing_campaign_out is None
            and vuln["threat_type"] in asset_threat_model.PHISHING_TRIGGER_TYPES
        ):
            phishing_campaign_out = _launch_scenario_phishing(
                db,
                asset_threat_model.PHISHING_TRIGGER_TYPES[vuln["threat_type"]],
                incident_id,
            )

    affected_assets = sorted({i["asset_name"] for i in incidents_out})
    return {
        "scenario_id": scenario_id,
        "scenario_name": (
            f"Exploração de vulnerabilidades em {len(affected_assets)} ativo(s) do inventário"
        ),
        "generated_at": datetime.now().isoformat(),
        "assets_scanned": len(profiles),
        "assets_affected": affected_assets,
        "vulnerabilities_found": sum(p["vulnerability_count"] for p in profiles),
        "playbooks_generated_by_ai": sum(
            1 for pb in playbooks_out.values() if pb.get("is_generated")
        ),
        "llm_available": config.llm_available(),
        "incidents": incidents_out,
        "playbooks": list(playbooks_out.values()),
        "training_missions": missions_out,
        "affected_users": list(affected_users.values()),
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

_ASSET_RELATION_TYPES = {
    "connected_to", "depends_on", "protects", "routes_to", "hosted_on",
    "connected_via", "communicates_with", "other",
}

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


@app.get("/api/assets/{asset_id}/relations", tags=["Ativos"])
def asset_relations(asset_id: int, db: Session = Depends(get_db)):
    """Lista as ligações de rede de um activo, nos sentidos de origem e destino."""
    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.is_active == True).first()
    if not asset:
        raise HTTPException(404, "Ativo não encontrado")
    relations = (
        db.query(AssetRelation)
        .filter(
            AssetRelation.is_active == True,
            (AssetRelation.source_asset_id == asset_id)
            | (AssetRelation.target_asset_id == asset_id),
        )
        .order_by(AssetRelation.created_at.desc())
        .all()
    )
    return [_asset_relation_to_dict(r) for r in relations]


@app.post("/api/assets/{asset_id}/relations", tags=["Ativos"])
def create_asset_relation(
    asset_id: int,
    relation: AssetRelationIn,
    db: Session = Depends(get_db),
):
    """Cria uma ligação dirigida entre dois activos activos da rede local."""
    source = db.query(Asset).filter(Asset.id == asset_id, Asset.is_active == True).first()
    target = db.query(Asset).filter(
        Asset.id == relation.target_asset_id, Asset.is_active == True
    ).first()
    if not source or not target:
        raise HTTPException(404, "Ativo de origem ou destino não encontrado")
    if asset_id == relation.target_asset_id:
        raise HTTPException(400, "Um ativo não pode relacionar-se consigo próprio")

    relation_type = relation.relation_type.strip().lower()
    if relation_type not in _ASSET_RELATION_TYPES:
        raise HTTPException(
            400,
            f"Tipo de relação inválido. Use: {', '.join(sorted(_ASSET_RELATION_TYPES))}",
        )

    existing = db.query(AssetRelation).filter(
        AssetRelation.source_asset_id == asset_id,
        AssetRelation.target_asset_id == relation.target_asset_id,
        AssetRelation.relation_type == relation_type,
        AssetRelation.is_active == True,
    ).first()
    if existing:
        raise HTTPException(409, "Esta relação entre os ativos já existe")

    asset_relation = AssetRelation(
        source_asset_id=asset_id,
        target_asset_id=relation.target_asset_id,
        relation_type=relation_type,
        protocol=relation.protocol,
        port=relation.port,
        network_zone=relation.network_zone,
        description=relation.description,
        tags=relation.tags or [],
    )
    db.add(asset_relation)
    db.commit()
    db.refresh(asset_relation)
    return _asset_relation_to_dict(asset_relation)


@app.delete("/api/asset-relations/{relation_id}", tags=["Ativos"])
def delete_asset_relation(relation_id: int, db: Session = Depends(get_db)):
    relation = db.query(AssetRelation).filter(
        AssetRelation.id == relation_id, AssetRelation.is_active == True
    ).first()
    if not relation:
        raise HTTPException(404, "Relação não encontrada")
    relation.is_active = False
    db.commit()
    return {"deleted": relation_id}


@app.get("/api/network/topology", tags=["Ativos"])
def network_topology(asset_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Devolve os nós e arestas activos para uma visão de topologia da rede."""
    assets_query = db.query(Asset).filter(Asset.is_active == True)
    if asset_id is not None:
        selected = db.query(Asset).filter(Asset.id == asset_id, Asset.is_active == True).first()
        if not selected:
            raise HTTPException(404, "Ativo não encontrado")
        assets_query = assets_query.filter(Asset.id == asset_id)
    assets = assets_query.order_by(Asset.name).all()
    asset_ids = {asset.id for asset in assets}
    relations = db.query(AssetRelation).filter(AssetRelation.is_active == True).all()
    relations = [
        relation for relation in relations
        if relation.source_asset_id in asset_ids and relation.target_asset_id in asset_ids
    ] if asset_id is not None else relations
    return {
        "nodes": [_asset_to_dict(asset) for asset in assets],
        "edges": [_asset_relation_to_dict(relation) for relation in relations],
    }


@app.get("/api/assets/{asset_id}/incidents", tags=["Ativos"])
def asset_incidents(asset_id: int, db: Session = Depends(get_db)):
    """Lista os incidentes/alertas associados a um ativo."""
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Ativo não encontrado")
    incidents = (
        db.query(Incident)
        .filter(Incident.asset_id == asset_id)
        .order_by(Incident.created_at.desc())
        .all()
    )
    return [_incident_to_dict(i) for i in incidents]


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
    if user.asset_id is not None:
        a = db.query(Asset).filter(Asset.id == user.asset_id, Asset.is_active == True).first()
        if not a:
            raise HTTPException(404, "Ativo não encontrado")
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


@app.put("/api/users/{user_id}", tags=["Utilizadores"])
def update_user(user_id: int, user: UserIn, db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "Utilizador não encontrado")
    existing = db.query(User).filter(User.username == user.username, User.id != user_id).first()
    if existing:
        raise HTTPException(400, "Username já existe")
    if user.asset_id is not None:
        a = db.query(Asset).filter(Asset.id == user.asset_id, Asset.is_active == True).first()
        if not a:
            raise HTTPException(404, "Ativo não encontrado")
    for field, value in user.model_dump().items():
        setattr(u, field, value)
    db.commit()
    db.refresh(u)
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
    old_risk = user.risk_score or 50.0
    user.risk_score = GamificationEngine.update_risk_score(
        user.risk_score or 50.0,
        user.missions_completed,
        result["score_percentage"],
        False,
    )

    _log_risk_event(
        db, user, "mission", scenario_id, sc.get("difficulty"),
        result["score_percentage"], old_risk,
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
    for provável — cria telemetria/incidente no SOCHAI. Fecha o ciclo L5 -> L1.
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

    # Se a triagem indica ameaça provável, gera um incidente no SOCHAI (L1 -> pipeline)
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
    _old_risk = user.risk_score or 50.0
    user.risk_score = reward["new_risk_score"]
    _log_risk_event(db, user, "phishing_report", "report", None, None, _old_risk)

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
            "Obrigado por reportar! Este email gerou um incidente no SOCHAI."
            if linked_incident_id else
            "Obrigado por reportar! O SOCHAI vai analisar o email."
        ),
    }


@app.get("/api/phishing/reports", tags=["Phishing Report"])
def list_phishing_reports(
    verdict: Optional[str] = None,
    reporter_id: Optional[int] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """Lista os reportes de phishing (fila de triagem para o analista SOCHAI)."""
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
    O analista SOCHAI confirma o veredicto final de um reporte.
    Ajusta a recompensa do colaborador conforme a confirmação
    (ex.: apanhar uma simulação real do SOCHAI é especialmente valorizado).
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
    _old_risk = user.risk_score or 50.0
    user.risk_score = reward["new_risk_score"]
    _log_risk_event(
        db, user, "phishing_sim", payload.outcome, campaign.difficulty, None, _old_risk,
    )
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


def _log_risk_event(db, user, event_type, detail, difficulty, score_pct, old_risk):
    db.add(RiskEvent(
        user_id=user.id, username=user.username, event_type=event_type,
        detail=str(detail)[:200], difficulty=difficulty, score_percentage=score_pct,
        risk_score=user.risk_score, risk_delta=round((user.risk_score or 0) - old_risk, 2),
        xp_total=user.xp_points or 0,
    ))


@app.get("/api/gamification/history", tags=["Gamificação"])
def gamification_history(db: Session = Depends(get_db)):
    """Histórico cronológico de alterações do HRS de todos os colaboradores."""
    return [{
        "user_id": e.user_id, "username": e.username, "event_type": e.event_type,
        "detail": e.detail, "difficulty": e.difficulty,
        "score_percentage": e.score_percentage, "risk_score": e.risk_score,
        "risk_delta": e.risk_delta, "xp_total": e.xp_total,
        "created_at": e.created_at.isoformat() if e.created_at else None,
    } for e in db.query(RiskEvent).order_by(RiskEvent.created_at, RiskEvent.id).all()]


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

# Alvo de SLA por severidade (minutos). São os mesmos limiares que o L4
# aplica à revisão HITL, aqui reutilizados para o ciclo completo do
# incidente (entrada do alerta → resolução).
_SLA_TARGET_MIN = {
    "CRITICA": config.HITL_SLA_CRITICAL,
    "ALTA": config.HITL_SLA_HIGH,
    "MEDIA": config.HITL_SLA_NORMAL,
    "BAIXA": config.HITL_SLA_NORMAL,
}


def _minutes_between(start, end) -> Optional[float]:
    """Minutos entre dois instantes; None se faltar um deles ou se for negativo."""
    if not start or not end:
        return None
    delta = (end - start).total_seconds() / 60
    return delta if delta >= 0 else None


def _mean(values: List[float]) -> Optional[float]:
    return round(sum(values) / len(values), 1) if values else None


def _compute_kpis(db: Session) -> Dict:
    """
    KPIs de desempenho do SOC — eficiência de deteção/resposta e precisão
    dos alertas. Tudo derivado dos timestamps já persistidos no incidente:
    created_at (entrada do alerta), reviewed_at (triagem HITL) e
    resolved_at (fecho).
    """
    incidents = db.query(Incident).all()

    time_to_investigate: List[float] = []
    time_to_resolve: List[float] = []
    resolve_by_sev: Dict[str, List[float]] = {}
    sla_met = 0
    sla_sample = 0

    for inc in incidents:
        sev = (inc.severity or "MEDIA").upper()

        t_inv = _minutes_between(inc.created_at, inc.reviewed_at)
        if t_inv is not None:
            time_to_investigate.append(t_inv)

        t_res = _minutes_between(inc.created_at, inc.resolved_at)
        if t_res is not None:
            time_to_resolve.append(t_res)
            resolve_by_sev.setdefault(sev, []).append(t_res)
            sla_sample += 1
            if t_res <= _SLA_TARGET_MIN.get(sev, config.HITL_SLA_NORMAL):
                sla_met += 1

    true_pos = sum(1 for i in incidents if i.is_true_positive is True)
    false_pos = sum(1 for i in incidents if i.is_true_positive is False)
    triaged = true_pos + false_pos

    return {
        # MTTD exigiria a hora a que o evento ocorreu na origem. A ingestão
        # só regista a hora a que o alerta entrou no pipeline, pelo que a
        # métrica fica por instrumentar em vez de ser estimada.
        "mttd_minutes": None,
        "mttd_note": "requer hora do evento na origem (não instrumentado na ingestão)",
        "mtti_minutes": _mean(time_to_investigate),
        "mttr_minutes": _mean(time_to_resolve),
        "mttr_by_severity": {s: _mean(v) for s, v in resolve_by_sev.items()},
        "sla_targets_minutes": _SLA_TARGET_MIN,
        "sla_compliance_pct": round(sla_met / sla_sample * 100, 1) if sla_sample else None,
        "sla_sample": sla_sample,
        "false_positive_rate_pct": round(false_pos / triaged * 100, 1) if triaged else None,
        "true_positive_rate_pct": round(true_pos / triaged * 100, 1) if triaged else None,
        "triaged_count": triaged,
        "alerts_per_confirmed_incident": (
            round(len(incidents) / true_pos, 1) if true_pos else None
        ),
        "total_alerts": len(incidents),
        "investigated_count": len(time_to_investigate),
        "resolved_count": len(time_to_resolve),
    }


@app.get("/api/analytics/kpis", tags=["Analytics"])
def analytics_kpis(db: Session = Depends(get_db)):
    """MTTI, MTTR, cumprimento de SLA e precisão dos alertas."""
    return _compute_kpis(db)


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
        "kpis": _compute_kpis(db),
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
        "asset_id": inc.asset_id,
        "asset_name": inc.asset.name if inc.asset else None,
        "asset_criticality": inc.asset.criticality if inc.asset else None,
        "asset_owners": (
            [{"user_id": u.id, "username": u.username, "full_name": u.full_name}
             for u in inc.asset.users]
            if inc.asset else []
        ),
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
        "services": a.services or [],
        "config": a.config or {},
        "is_active": a.is_active,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "linked_users": [
            {"user_id": u.id, "username": u.username, "full_name": u.full_name}
            for u in a.users
        ],
    }


def _asset_relation_to_dict(relation: AssetRelation) -> Dict:
    return {
        "id": relation.id,
        "source_asset_id": relation.source_asset_id,
        "source_asset_name": relation.source_asset.name if relation.source_asset else None,
        "target_asset_id": relation.target_asset_id,
        "target_asset_name": relation.target_asset.name if relation.target_asset else None,
        "relation_type": relation.relation_type,
        "protocol": relation.protocol,
        "port": relation.port,
        "network_zone": relation.network_zone,
        "description": relation.description,
        "tags": relation.tags or [],
        "is_active": relation.is_active,
        "created_at": relation.created_at.isoformat() if relation.created_at else None,
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
        "asset_id": u.asset_id,
        "asset_name": u.asset.name if u.asset else None,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


# ================================================================== #
# Entry point
# ================================================================== #

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_main:app", host="0.0.0.0", port=config.WEBHOOK_PORT, reload=False)
