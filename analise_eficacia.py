"""
analise_eficacia.py — Análise de eficácia do treino gamificado (L5).

Responde à pergunta de investigação:

    Os resultados de gamificação dos colaboradores reduzem o risco do fator
    humano e melhoram o score médio da organização perante cenários e
    incidentes?

PRINCÍPIO METODOLÓGICO CENTRAL
------------------------------
O Human Risk Score (HRS) é calculado por update_risk_score() A PARTIR das
missões de treino. Demonstrar que "o colaborador treinou e o HRS desceu" é,
por isso, uma tautologia — não é um resultado. Este módulo evita a
circularidade usando como variável dependente apenas COMPORTAMENTO OBSERVADO
fora da fórmula do score:

    X (independente) : missões concluídas e score médio de treino ANTES da campanha
    Y (dependente)   : desfecho real na campanha de phishing (clicou / reportou),
                       tempo até à ação, e incidentes de origem humana

Análises produzidas:

    A1  Pré/pós intra-sujeito .......... McNemar exato sobre clicou/não clicou
    A2  Dose-resposta .................. regressão logística + bootstrap por
                                         cluster (colaborador) e teste de
                                         tendência de Cochran-Armitage
    A3  Validade preditiva ............. corte temporal: o HRS até t prevê o
                                         comportamento em t+1? AUC, Brier,
                                         calibração, lift
    A4  Score organizacional ........... HRI ponderado pela criticidade do
                                         ativo + métricas por campanha
    A5  HRI vs incidentes .............. correlação desfasada HRI(t) → incidentes(t+1)
    A6  Poder estatístico .............. que n é preciso para detetar o efeito

Cada análise declara requisitos mínimos de dados e devolve INSUFICIENTE (com
o que falta) em vez de produzir números sem validade.

Uso:
    python analise_eficacia.py                      # base de dados real
    python analise_eficacia.py --demo               # painel sintético (valida o pipeline)
    python analise_eficacia.py --demo --n-users 400 --n-campanhas 6 --seed 42
"""

import argparse
import json
import math
import os
import random
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import numpy as np
from scipy import stats
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, roc_auc_score

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "soc_database.db")
JSON_OUT = os.path.join(BASE_DIR, "analise_eficacia_resultados.json")

# ─────────────────────────────────────────────────────────────────────────────
# Parâmetros metodológicos (explícitos, para poderem ser citados e criticados)
# ─────────────────────────────────────────────────────────────────────────────

# Peso de cada colaborador no índice organizacional, pela criticidade do ativo
# que lhe está associado (users.asset_id -> assets.criticality). A média simples
# esconde a concentração de risco: 3 pessoas de risco alto com acesso crítico
# pesam mais do que 50 de risco baixo sem acesso.
CRITICALITY_WEIGHTS = {"CRITICO": 4.0, "ALTO": 3.0, "MEDIO": 2.0, "BAIXO": 1.0}
DEFAULT_WEIGHT = 1.0

# Tipos de incidente considerados de origem humana. Classificação por palavra-
# chave no título/descrição — é um PROXY, não uma atribuição de causa. A tabela
# incidents não tem campo de causa-raiz (ver "Lacunas de instrumentação").
HUMAN_FACTOR_TYPES = {"phishing", "social_engineering", "ransomware", "malware"}
INCIDENT_KEYWORDS = {
    "phishing": ("phishing", "email suspeito", "credential"),
    "social_engineering": ("social", "engenharia social", "pretexting", "usb"),
    "ransomware": ("ransomware", "encripta", "resgate"),
    "malware": ("malware", "trojan", "vírus", "virus"),
    "intrusion": ("intrusion", "intrusão", "acesso não autorizado", "brute"),
    "scan": ("scan", "varrimento", "port scan"),
    "dos": ("ddos", "denial of service", "negação de serviço"),
    "exfiltration": ("exfiltra", "fuga de dados", "data leak"),
}

# Requisitos mínimos de dados por análise. Abaixo destes valores o resultado
# não tem validade e o módulo recusa-se a produzi-lo.
MIN_N = {
    "mcnemar_pares": 10,        # colaboradores com campanha antes E depois do treino
    "mcnemar_discordantes": 5,  # pares que mudaram de comportamento
    "logit_obs": 40,            # exposições (colaborador × campanha) com desfecho
    "logit_eventos": 8,         # cliques observados (regra ~10 eventos por preditor)
    "auc_obs": 30,              # exposições no conjunto de validação temporal
    "auc_por_classe": 5,        # mínimo de cliques e de não-cliques
    "hri_users": 5,             # colaboradores com HRS conhecido
    "lag_periodos": 6,          # meses emparelhados HRI(t) → incidentes(t+1)
}

BOOTSTRAP_B = 2000              # réplicas do bootstrap por cluster
ALPHA = 0.05
POWER_TARGET = 0.80
EFEITO_ALVO_PP = 10.0           # redução de 10 p.p. na taxa de cliques

# Efeito comportamental assumido na simulação (--demo). NÃO é um resultado:
# é a premissa que a simulação impõe. Ver aviso no relatório.
DEMO_BASE_CLICK = 0.42          # taxa de cliques na campanha de baseline
DEMO_EFEITO_MISSAO = 0.055      # redução da odds de clique por missão concluída
DEMO_EFEITO_SCORE = 0.010       # redução adicional por ponto percentual de score


# ─────────────────────────────────────────────────────────────────────────────
# Estruturas de dados
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Observation:
    """Uma exposição: um colaborador numa campanha de phishing simulado."""
    user_id: int
    username: str
    department: Optional[str]
    criticality: Optional[str]
    campaign_id: int
    campaign_difficulty: Optional[str]
    sent_at: datetime
    outcome: str                        # clicked | reported | ignored | pending
    time_to_action: Optional[float]
    missions_before: int                # exposição ao treino ANTES desta campanha
    mean_score_before: Optional[float]  # score médio de treino ANTES desta campanha
    risk_before: Optional[float]        # HRS ANTES desta campanha (para A3)

    @property
    def engaged(self) -> bool:
        """Exposições ainda por resolver (pending) não são desfecho observado."""
        return self.outcome in ("clicked", "reported", "ignored")

    @property
    def clicked(self) -> int:
        return 1 if self.outcome == "clicked" else 0

    @property
    def reported(self) -> int:
        return 1 if self.outcome == "reported" else 0


@dataclass
class UserRow:
    user_id: int
    username: str
    department: Optional[str]
    criticality: Optional[str]
    risk_score: Optional[float]
    missions_completed: int
    xp_points: int


@dataclass
class IncidentRow:
    incident_id: str
    created_at: datetime
    resolved_at: Optional[datetime]
    itype: str
    severity: Optional[str]

    @property
    def human_factor(self) -> bool:
        return self.itype in HUMAN_FACTOR_TYPES


@dataclass
class RiskPoint:
    """Um ponto do histórico do HRS (tabela risk_events)."""
    user_id: int
    created_at: datetime
    event_type: str
    score_percentage: Optional[float]
    risk_score: Optional[float]


@dataclass
class Dataset:
    observations: List[Observation]
    users: List[UserRow]
    incidents: List[IncidentRow]
    risk_points: List[RiskPoint]
    source: str
    synthetic: bool
    avisos: List[str] = field(default_factory=list)

    @property
    def engaged(self) -> List[Observation]:
        return [o for o in self.observations if o.engaged]


# ─────────────────────────────────────────────────────────────────────────────
# Leitura da base de dados
# ─────────────────────────────────────────────────────────────────────────────

def _dt(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
    return None


def classify_incident(title: str, description: str) -> str:
    """Classifica o tipo de incidente por palavra-chave. Proxy documentado."""
    blob = f"{title or ''} {description or ''}".lower()
    for itype, keywords in INCIDENT_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return itype
    return "outro"


def load_from_db(db_path: str = DB_PATH) -> Dataset:
    """Constrói o painel longitudinal a partir da base de dados do SOCHAI."""
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Base de dados não encontrada: {db_path}")

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    avisos: List[str] = []

    # Colaboradores + criticidade do ativo associado
    users: List[UserRow] = []
    user_by_id: Dict[int, UserRow] = {}
    for r in con.execute(
        """
        SELECT u.id, u.username, u.department, u.risk_score,
               u.missions_completed, u.xp_points, a.criticality
        FROM users u
        LEFT JOIN assets a ON a.id = u.asset_id
        """
    ):
        row = UserRow(
            user_id=r["id"], username=r["username"], department=r["department"],
            criticality=r["criticality"], risk_score=r["risk_score"],
            missions_completed=r["missions_completed"] or 0,
            xp_points=r["xp_points"] or 0,
        )
        users.append(row)
        user_by_id[row.user_id] = row

    # Histórico do HRS — é o que permite reconstruir a exposição ao treino
    # num instante passado (covariável variável no tempo).
    risk_points: List[RiskPoint] = []
    for r in con.execute(
        "SELECT user_id, created_at, event_type, score_percentage, risk_score "
        "FROM risk_events ORDER BY created_at"
    ):
        created = _dt(r["created_at"])
        if created is None or r["user_id"] is None:
            continue
        risk_points.append(RiskPoint(
            user_id=r["user_id"], created_at=created, event_type=r["event_type"],
            score_percentage=r["score_percentage"], risk_score=r["risk_score"],
        ))

    n_missions_tbl = con.execute("SELECT COUNT(*) FROM user_missions").fetchone()[0]
    if n_missions_tbl == 0:
        avisos.append(
            "user_missions está vazia — a exposição ao treino é reconstruída a "
            "partir de risk_events (event_type='mission'). Popular user_missions "
            "dá um painel por missão, mais fino e auditável."
        )

    # Exposições: alvos das campanhas
    observations: List[Observation] = []
    for r in con.execute(
        """
        SELECT t.user_id, t.username, t.department, t.campaign_id, t.outcome,
               t.sent_at, t.time_to_action_seconds, c.difficulty
        FROM phishing_targets t
        LEFT JOIN phishing_campaigns c ON c.id = t.campaign_id
        ORDER BY t.sent_at
        """
    ):
        sent_at = _dt(r["sent_at"])
        if sent_at is None or r["user_id"] is None:
            continue
        uid = r["user_id"]
        before = [p for p in risk_points if p.user_id == uid and p.created_at < sent_at]
        missions = [p for p in before if p.event_type == "mission"]
        scores = [p.score_percentage for p in missions if p.score_percentage is not None]
        risk_before = before[-1].risk_score if before else None

        user = user_by_id.get(uid)
        observations.append(Observation(
            user_id=uid, username=r["username"],
            department=r["department"] or (user.department if user else None),
            criticality=user.criticality if user else None,
            campaign_id=r["campaign_id"], campaign_difficulty=r["difficulty"],
            sent_at=sent_at, outcome=r["outcome"] or "pending",
            time_to_action=r["time_to_action_seconds"],
            missions_before=len(missions),
            mean_score_before=(sum(scores) / len(scores)) if scores else None,
            risk_before=risk_before,
        ))

    # Incidentes
    incidents: List[IncidentRow] = []
    for r in con.execute(
        "SELECT incident_id, title, description, severity, created_at, resolved_at FROM incidents"
    ):
        created = _dt(r["created_at"])
        if created is None:
            continue
        incidents.append(IncidentRow(
            incident_id=r["incident_id"], created_at=created,
            resolved_at=_dt(r["resolved_at"]), severity=r["severity"],
            itype=classify_incident(r["title"], r["description"]),
        ))

    con.close()

    pend = sum(1 for o in observations if not o.engaged)
    if pend:
        avisos.append(
            f"{pend} de {len(observations)} exposições estão em 'pending' — não "
            "contam como desfecho observado. Fechar as campanhas (marcar "
            "ignored após o prazo) é condição para a análise ter n utilizável."
        )

    return Dataset(
        observations=observations, users=users, incidents=incidents,
        risk_points=risk_points, source=f"base de dados ({os.path.basename(db_path)})",
        synthetic=False, avisos=avisos,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Geração de painel sintético (--demo) — valida o pipeline, não a eficácia
# ─────────────────────────────────────────────────────────────────────────────

def simulate_dataset(n_users: int = 200, n_campanhas: int = 5, seed: int = 42) -> Dataset:
    """
    Gera um painel sintético com o motor REAL de gamificação.

    Desenho: quase-experimental com grupo de controlo.
      - campanha 0  : baseline, antes de qualquer treino (ambos os braços)
      - treino      : só o braço de tratamento completa as 5 missões base
      - campanhas 1+: ambos os braços, para permitir diferenças-em-diferenças

    AVISO: a relação treino → comportamento é IMPOSTA por DEMO_EFEITO_MISSAO e
    DEMO_EFEITO_SCORE. Qualquer efeito detetado aqui foi colocado à mão. Serve
    para demonstrar a sensibilidade e o poder estatístico do instrumento de
    medição — nunca como evidência de eficácia.
    """
    from gamification import GamificationEngine  # importado só no modo demo

    engine = GamificationEngine()
    rng = random.Random(seed)
    scenario_ids = ["SC-001", "SC-002", "SC-003", "SC-004", "SC-005"]
    criticidades = list(CRITICALITY_WEIGHTS.keys())
    departamentos = ["Financeiro", "TI", "Comercial", "RH", "Operações"]

    t0 = datetime(2026, 1, 15, 9, 0)
    datas = [t0 + timedelta(days=45 * k) for k in range(n_campanhas)]
    data_treino = t0 + timedelta(days=20)  # entre a campanha 0 e a campanha 1

    users: List[UserRow] = []
    risk_points: List[RiskPoint] = []
    observations: List[Observation] = []

    for uid in range(1, n_users + 1):
        tratado = uid % 2 == 0                     # alocação alternada ≈ 50/50
        competencia = rng.betavariate(2.0, 2.0)    # aptidão latente em [0,1]
        criticality = rng.choice(criticidades)
        user = UserRow(
            user_id=uid, username=f"colab{uid:04d}",
            department=rng.choice(departamentos), criticality=criticality,
            risk_score=50.0, missions_completed=0, xp_points=0,
        )

        risk = 50.0
        missions_done = 0
        scores: List[float] = []

        for k, data in enumerate(datas):
            # Treino acontece entre a campanha 0 e a 1, só no braço tratado
            if k == 1 and tratado:
                for i, sid in enumerate(scenario_ids):
                    scenario = engine.get_scenario(sid)
                    answers = []
                    for q in scenario["questions"]:
                        p_ok = 0.25 + 0.70 * competencia
                        if rng.random() < p_ok:
                            answers.append(q["correct"])
                        else:
                            erradas = [j for j in range(len(q["options"])) if j != q["correct"]]
                            answers.append(rng.choice(erradas))
                    result = engine.evaluate_mission(answers, scenario)
                    if result["passed"]:
                        missions_done += 1
                    scores.append(result["score_percentage"])
                    user.xp_points += result["xp_earned"]
                    risk = GamificationEngine.update_risk_score(
                        risk, missions_done, result["score_percentage"], False
                    )
                    risk_points.append(RiskPoint(
                        user_id=uid,
                        created_at=data_treino + timedelta(minutes=10 * i),
                        event_type="mission",
                        score_percentage=result["score_percentage"],
                        risk_score=risk,
                    ))
                user.missions_completed = missions_done

            mean_score = (sum(scores) / len(scores)) if scores else None

            # Comportamento na campanha — premissa imposta (ver docstring)
            logit = math.log(DEMO_BASE_CLICK / (1 - DEMO_BASE_CLICK))
            logit -= 1.6 * (competencia - 0.5)
            logit -= DEMO_EFEITO_MISSAO * missions_done
            if mean_score is not None:
                logit -= DEMO_EFEITO_SCORE * mean_score
            p_click = 1 / (1 + math.exp(-logit))

            u = rng.random()
            if u < p_click:
                outcome = "clicked"
            elif u < p_click + (0.20 + 0.45 * competencia) * (1 - p_click):
                outcome = "reported"
            else:
                outcome = "ignored"

            observations.append(Observation(
                user_id=uid, username=user.username, department=user.department,
                criticality=criticality, campaign_id=k + 1,
                campaign_difficulty="INTERMEDIO",
                sent_at=data + timedelta(minutes=rng.randint(0, 240)),
                outcome=outcome,
                time_to_action=round(rng.uniform(15, 900), 1),
                missions_before=missions_done,
                mean_score_before=mean_score,
                risk_before=risk,
            ))

            reward = GamificationEngine.reward_for_outcome(outcome, risk)
            risk = reward["new_risk_score"]
            user.xp_points += reward["xp_delta"]
            risk_points.append(RiskPoint(
                user_id=uid, created_at=data + timedelta(minutes=250),
                event_type="phishing_sim", score_percentage=None, risk_score=risk,
            ))

        user.risk_score = risk
        users.append(user)

    # Incidentes sintéticos: taxa mensal proporcional ao HRI do mês anterior.
    # Também é uma premissa imposta — serve só para exercitar a análise A5.
    incidents: List[IncidentRow] = []
    inc_seq = 0
    meses = sorted({(p.created_at.year, p.created_at.month) for p in risk_points})
    hri_mes = {}
    for ano, mes in meses:
        vals = [p.risk_score for p in risk_points
                if (p.created_at.year, p.created_at.month) == (ano, mes)
                and p.risk_score is not None]
        hri_mes[(ano, mes)] = sum(vals) / len(vals) if vals else None
    for (ano, mes), hri in hri_mes.items():
        if hri is None:
            continue
        nxt = (ano + 1, 1) if mes == 12 else (ano, mes + 1)
        lam = max(0.0, hri / 8.0)
        for _ in range(int(rng.gauss(lam, 1.5)) if lam > 0 else 0):
            inc_seq += 1
            itype = rng.choice(sorted(HUMAN_FACTOR_TYPES)) if rng.random() < 0.6 else "intrusion"
            criado = datetime(nxt[0], nxt[1], rng.randint(1, 28), rng.randint(8, 18))
            incidents.append(IncidentRow(
                incident_id=f"INC-SIM-{inc_seq:05d}", created_at=criado,
                resolved_at=criado + timedelta(hours=rng.uniform(1, 72)),
                itype=itype, severity=rng.choice(["BAIXA", "MEDIA", "ALTA", "CRITICA"]),
            ))

    return Dataset(
        observations=observations, users=users, incidents=incidents,
        risk_points=risk_points,
        source=f"simulação (n={n_users}, {n_campanhas} campanhas, seed={seed})",
        synthetic=True,
        avisos=[
            "Painel SINTÉTICO. A relação treino → comportamento foi imposta pelos "
            "parâmetros DEMO_*. Os resultados demonstram que o pipeline de medição "
            "deteta o efeito — não que a gamificação seja eficaz.",
        ],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Utilitários estatísticos
# ─────────────────────────────────────────────────────────────────────────────

def _insuficiente(motivo: str, necessario: str) -> Dict:
    return {"status": "INSUFICIENTE", "motivo": motivo, "necessario": necessario}


def wilson_ci(successes: int, n: int, alpha: float = ALPHA) -> Tuple[float, float]:
    """IC de Wilson para uma proporção — correto com n pequeno (ao contrário do normal)."""
    if n == 0:
        return (0.0, 0.0)
    z = stats.norm.ppf(1 - alpha / 2)
    p = successes / n
    denom = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def cochran_armitage(doses: List[float], n_i: List[int], r_i: List[int]) -> Dict:
    """Teste de tendência de Cochran-Armitage para proporções ordenadas."""
    N = sum(n_i)
    R = sum(r_i)
    if N == 0 or R == 0 or R == N:
        return {"status": "INSUFICIENTE", "motivo": "sem variação na variável resposta"}
    p_bar = R / N
    T = sum(d * (r - n * p_bar) for d, n, r in zip(doses, n_i, r_i))
    s1 = sum(n * d**2 for n, d in zip(n_i, doses))
    s2 = sum(n * d for n, d in zip(n_i, doses))
    var = p_bar * (1 - p_bar) * (s1 - s2**2 / N)
    if var <= 0:
        return {"status": "INSUFICIENTE", "motivo": "variância nula (dose constante)"}
    z = T / math.sqrt(var)
    return {
        "status": "OK",
        "z": round(z, 3),
        "p_value": round(2 * (1 - stats.norm.cdf(abs(z))), 5),
    }


def n_por_grupo(p0: float, p1: float, alpha: float = ALPHA, power: float = POWER_TARGET) -> Optional[int]:
    """n por braço para detetar a diferença entre duas proporções independentes."""
    if not (0 < p0 < 1 and 0 < p1 < 1) or abs(p0 - p1) < 1e-9:
        return None
    z_a = stats.norm.ppf(1 - alpha / 2)
    z_b = stats.norm.ppf(power)
    p_bar = (p0 + p1) / 2
    num = (z_a * math.sqrt(2 * p_bar * (1 - p_bar))
           + z_b * math.sqrt(p0 * (1 - p0) + p1 * (1 - p1))) ** 2
    return int(math.ceil(num / (p0 - p1) ** 2))


def efeito_detetavel(p0: float, n: int, alpha: float = ALPHA, power: float = POWER_TARGET) -> Optional[float]:
    """Menor redução (em p.p.) detetável com n por braço — procura por bisseção."""
    if n <= 0 or not 0 < p0 < 1:
        return None
    lo, hi = 0.001, p0 - 1e-4
    if hi <= lo:
        return None
    for _ in range(60):
        mid = (lo + hi) / 2
        req = n_por_grupo(p0, p0 - mid, alpha, power)
        if req is None:
            lo = mid
        elif req > n:
            lo = mid
        else:
            hi = mid
    return round(hi * 100, 1)


# ─────────────────────────────────────────────────────────────────────────────
# A1 — Pré/pós intra-sujeito (McNemar exato)
# ─────────────────────────────────────────────────────────────────────────────

def a1_pre_pos(ds: Dataset) -> Dict:
    """
    Compara o comportamento do MESMO colaborador antes e depois do treino.

    Emparelhamento por sujeito: cada colaborador contribui com UMA exposição
    antes (a última pré-treino) e UMA depois (a primeira pós-treino). Usar
    "clicou em alguma das campanhas seguintes" seria enviesado — com mais
    exposições depois do que antes, a probabilidade de pelo menos um clique
    sobe por construção, e o teste acusaria uma degradação inexistente.

    Usa-se McNemar exato (binomial sobre os pares discordantes) — o
    qui-quadrado de independência seria incorreto, porque as duas observações
    pertencem ao mesmo sujeito e não são independentes.
    """
    # Instante da primeira missão de cada colaborador = momento do "tratamento"
    t_treino: Dict[int, datetime] = {}
    for p in sorted(ds.risk_points, key=lambda x: x.created_at):
        if p.event_type == "mission" and p.user_id not in t_treino:
            t_treino[p.user_id] = p.created_at

    pares = []
    for uid, t0 in t_treino.items():
        obs = sorted((o for o in ds.engaged if o.user_id == uid), key=lambda x: x.sent_at)
        pre = [o for o in obs if o.sent_at < t0]
        pos = [o for o in obs if o.sent_at >= t0]
        if not pre or not pos:
            continue
        # Uma exposição de cada lado, as mais próximas do treino: mantém o
        # número de tentativas igual nos dois braços do par.
        pares.append((pre[-1].clicked, pos[0].clicked))

    if len(pares) < MIN_N["mcnemar_pares"]:
        return _insuficiente(
            f"apenas {len(pares)} colaborador(es) com campanha antes E depois do treino",
            f"≥ {MIN_N['mcnemar_pares']} pares; exige uma campanha de baseline "
            "ANTES de abrir o treino a cada colaborador",
        )

    b = sum(1 for pre, pos in pares if pre == 1 and pos == 0)   # melhorou
    c = sum(1 for pre, pos in pares if pre == 0 and pos == 1)   # piorou
    n = len(pares)
    taxa_pre = sum(p for p, _ in pares) / n
    taxa_pos = sum(q for _, q in pares) / n

    resultado = {
        "status": "OK",
        "n_pares": n,
        "taxa_clique_pre": round(taxa_pre * 100, 1),
        "taxa_clique_pos": round(taxa_pos * 100, 1),
        "reducao_absoluta_pp": round((taxa_pre - taxa_pos) * 100, 1),
        "reducao_relativa_pct": round((taxa_pre - taxa_pos) / taxa_pre * 100, 1) if taxa_pre else None,
        "melhoraram": b,
        "pioraram": c,
        "discordantes": b + c,
    }

    if b + c < MIN_N["mcnemar_discordantes"]:
        resultado["teste"] = _insuficiente(
            f"apenas {b + c} pares discordantes",
            f"≥ {MIN_N['mcnemar_discordantes']} para o teste exato ter sentido",
        )
        return resultado

    p_value = stats.binomtest(b, b + c, 0.5, alternative="two-sided").pvalue
    resultado["teste"] = {
        "nome": "McNemar exato (binomial sobre discordantes)",
        "p_value": round(float(p_value), 5),
        "significativo": bool(p_value < ALPHA),
    }
    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# A2 — Dose-resposta (logística + bootstrap por cluster + tendência)
# ─────────────────────────────────────────────────────────────────────────────

def a2_dose_resposta(ds: Dataset, b_boot: int = BOOTSTRAP_B, seed: int = 42) -> Dict:
    """
    Modela P(clique) em função da exposição ao treino acumulada até à campanha.

    Sem statsmodels no projeto, o equivalente a um modelo de efeitos mistos é
    obtido por BOOTSTRAP POR CLUSTER: reamostram-se COLABORADORES (não
    observações), o que respeita a correlação intra-sujeito das medições
    repetidas e produz ICs válidos para os odds ratios.
    """
    obs = [o for o in ds.engaged if o.missions_before is not None]
    if len(obs) < MIN_N["logit_obs"]:
        return _insuficiente(
            f"apenas {len(obs)} exposições com desfecho observado",
            f"≥ {MIN_N['logit_obs']} exposições (colaborador × campanha) fechadas",
        )

    y = np.array([o.clicked for o in obs])
    if y.sum() < MIN_N["logit_eventos"] or (len(y) - y.sum()) < MIN_N["logit_eventos"]:
        return _insuficiente(
            f"{int(y.sum())} cliques e {int(len(y) - y.sum())} não-cliques",
            f"≥ {MIN_N['logit_eventos']} de cada — abaixo disto a logística é instável",
        )

    X = np.array([[o.missions_before, o.mean_score_before or 0.0] for o in obs])
    grupos = np.array([o.user_id for o in obs])

    def _fit(Xf, yf) -> Optional[np.ndarray]:
        if len(set(yf.tolist())) < 2:
            return None
        try:
            # C=np.inf => sem regularização (o equivalente ao antigo penalty=None,
            # depreciado no scikit-learn 1.8). Interessa o coeficiente não enviesado.
            m = LogisticRegression(C=np.inf, solver="lbfgs", max_iter=1000)
            m.fit(Xf, yf)
            return m.coef_[0]
        except Exception:
            return None

    coef = _fit(X, y)
    if coef is None:
        return _insuficiente("o modelo não convergiu", "mais variação nos preditores")

    # Bootstrap por cluster (colaborador)
    rng = np.random.default_rng(seed)
    uids = np.unique(grupos)
    idx_por_uid = {u: np.where(grupos == u)[0] for u in uids}
    amostras: List[np.ndarray] = []
    for _ in range(b_boot):
        escolhidos = rng.choice(uids, size=len(uids), replace=True)
        idx = np.concatenate([idx_por_uid[u] for u in escolhidos])
        c = _fit(X[idx], y[idx])
        if c is not None:
            amostras.append(c)

    def _or_ic(pos: int, escala: float) -> Dict:
        est = math.exp(coef[pos] * escala)
        if len(amostras) < 100:
            return {"odds_ratio": round(est, 3), "ic95": None,
                    "nota": f"apenas {len(amostras)} réplicas convergiram"}
        vals = np.array([math.exp(a[pos] * escala) for a in amostras])
        return {
            "odds_ratio": round(est, 3),
            "ic95": [round(float(np.percentile(vals, 2.5)), 3),
                     round(float(np.percentile(vals, 97.5)), 3)],
        }

    resultado = {
        "status": "OK",
        "n_exposicoes": len(obs),
        "n_colaboradores": int(len(uids)),
        "cliques": int(y.sum()),
        "replicas_bootstrap": len(amostras),
        "or_por_missao": _or_ic(0, 1.0),
        "or_por_10pp_score": _or_ic(1, 10.0),
    }
    for chave in ("or_por_missao", "or_por_10pp_score"):
        ic = resultado[chave].get("ic95")
        resultado[chave]["protetor_significativo"] = bool(ic and ic[1] < 1.0)

    # Tendência por tercis de exposição
    doses = np.array([o.missions_before for o in obs], dtype=float)
    if len(np.unique(doses)) >= 3:
        q1, q2 = np.percentile(doses, [33.3, 66.6])
        tercis = [(-math.inf, q1), (q1, q2), (q2, math.inf)]
        n_i, r_i, rotulos = [], [], []
        for lo, hi in tercis:
            sel = (doses > lo) & (doses <= hi) if lo != -math.inf else (doses <= hi)
            n_i.append(int(sel.sum()))
            r_i.append(int(y[sel].sum()))
            rotulos.append(f"({lo if lo != -math.inf else 0:.0f}, {hi if hi != math.inf else doses.max():.0f}]")
        resultado["tendencia"] = {
            "tercis": rotulos,
            "n_por_tercil": n_i,
            "cliques_por_tercil": r_i,
            "taxa_clique_por_tercil": [round(r / n * 100, 1) if n else None for n, r in zip(n_i, r_i)],
            "cochran_armitage": cochran_armitage([0.0, 1.0, 2.0], n_i, r_i),
        }
    else:
        resultado["tendencia"] = _insuficiente(
            "menos de 3 níveis distintos de exposição ao treino",
            "colaboradores com números de missões diferentes entre si",
        )
    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# A3 — Validade preditiva (corte temporal)
# ─────────────────────────────────────────────────────────────────────────────

def a3_validade_preditiva(ds: Dataset) -> Dict:
    """
    O HRS acumulado até ao instante t prevê o comportamento em t+1?

    Esta é a análise que quebra a circularidade: o alvo é o desfecho de uma
    campanha que ainda NÃO tinha entrado no cálculo do score. Um AUC ≈ 0.5
    significa que o score não discrimina — resultado igualmente publicável.
    """
    pares: List[Tuple[float, int]] = []
    por_user: Dict[int, List[Observation]] = {}
    for o in ds.engaged:
        if o.risk_before is not None:
            por_user.setdefault(o.user_id, []).append(o)
    for uid, lista in por_user.items():
        lista.sort(key=lambda x: x.sent_at)
        for o in lista[1:]:   # a 1ª exposição não tem histórico anterior
            pares.append((float(o.risk_before), o.clicked))

    if len(pares) < MIN_N["auc_obs"]:
        return _insuficiente(
            f"apenas {len(pares)} exposições com HRS anterior conhecido",
            f"≥ {MIN_N['auc_obs']}; exige ≥ 2 campanhas por colaborador e "
            "registo do HRS em risk_events antes de cada uma",
        )

    scores = np.array([p for p, _ in pares], dtype=float)
    y = np.array([c for _, c in pares])
    if y.sum() < MIN_N["auc_por_classe"] or (len(y) - y.sum()) < MIN_N["auc_por_classe"]:
        return _insuficiente(
            f"{int(y.sum())} cliques e {int(len(y) - y.sum())} não-cliques no conjunto de validação",
            f"≥ {MIN_N['auc_por_classe']} de cada classe",
        )

    auc = float(roc_auc_score(y, scores))
    brier = float(brier_score_loss(y, np.clip(scores / 100.0, 0, 1)))

    # Calibração por bandas de risco
    bandas = [(0, 20), (20, 40), (40, 60), (60, 80), (80, 100.01)]
    calibracao = []
    for lo, hi in bandas:
        sel = (scores >= lo) & (scores < hi)
        n = int(sel.sum())
        if n == 0:
            continue
        calibracao.append({
            "banda_hrs": f"[{lo}, {min(hi, 100):.0f})",
            "n": n,
            "hrs_medio": round(float(scores[sel].mean()), 1),
            "taxa_clique_observada_pct": round(float(y[sel].mean()) * 100, 1),
        })

    # Lift no tercil de maior risco
    corte = float(np.percentile(scores, 66.6))
    topo = scores >= corte
    taxa_topo = float(y[topo].mean()) if topo.sum() else 0.0
    taxa_geral = float(y.mean())

    return {
        "status": "OK",
        "n_validacao": len(pares),
        "auc_roc": round(auc, 3),
        "interpretacao_auc": (
            "sem poder discriminativo" if auc < 0.6 else
            "discriminação fraca" if auc < 0.7 else
            "discriminação aceitável" if auc < 0.8 else
            "discriminação boa"
        ),
        "brier_score": round(brier, 4),
        "nota_brier": (
            "O HRS não foi concebido como probabilidade; o Brier aqui usa HRS/100 "
            "como proxy. Para o usar como probabilidade, recalibrar (Platt/isotónica) "
            "em dados de treino separados."
        ),
        "calibracao": calibracao,
        "lift_tercil_superior": round(taxa_topo / taxa_geral, 2) if taxa_geral else None,
        "taxa_clique_tercil_superior_pct": round(taxa_topo * 100, 1),
        "taxa_clique_global_pct": round(taxa_geral * 100, 1),
    }


# ─────────────────────────────────────────────────────────────────────────────
# A4 — Score organizacional (HRI) e métricas por campanha
# ─────────────────────────────────────────────────────────────────────────────

def a4_score_organizacional(ds: Dataset) -> Dict:
    """
    Índice de risco humano da organização e métricas comportamentais agregadas.

    O HRI pondera cada colaborador pela criticidade do ativo que lhe está
    associado: a média simples trata quem tem acesso a sistemas críticos como
    quem não tem, e é isso que faz o indicador enganar a direção.
    """
    com_score = [u for u in ds.users if u.risk_score is not None]
    if len(com_score) < MIN_N["hri_users"]:
        return _insuficiente(
            f"apenas {len(com_score)} colaborador(es) com HRS",
            f"≥ {MIN_N['hri_users']} colaboradores com risk_score preenchido",
        )

    media_simples = sum(u.risk_score for u in com_score) / len(com_score)
    pesos = [CRITICALITY_WEIGHTS.get(u.criticality, DEFAULT_WEIGHT) for u in com_score]
    hri = sum(u.risk_score * w for u, w in zip(com_score, pesos)) / sum(pesos)
    sem_ativo = sum(1 for u in com_score if u.criticality is None)

    # Distribuição por banda de risco
    def banda(v: float) -> str:
        return "BAIXO" if v < 20 else "MEDIO" if v < 50 else "ALTO"

    distribuicao: Dict[str, int] = {"BAIXO": 0, "MEDIO": 0, "ALTO": 0}
    for u in com_score:
        distribuicao[banda(u.risk_score)] += 1

    # Métricas comportamentais por campanha
    por_campanha: Dict[int, List[Observation]] = {}
    for o in ds.observations:
        por_campanha.setdefault(o.campaign_id, []).append(o)

    campanhas = []
    for cid in sorted(por_campanha, key=lambda c: min(x.sent_at for x in por_campanha[c])):
        alvos = por_campanha[cid]
        fechados = [o for o in alvos if o.engaged]
        clicked = sum(o.clicked for o in fechados)
        reported = sum(o.reported for o in fechados)
        tempos = [o.time_to_action for o in fechados if o.time_to_action is not None]
        n_f = len(fechados)
        lo, hi = wilson_ci(clicked, n_f) if n_f else (None, None)
        resiliencia = (round(reported / (reported + clicked) * 100, 1)
                       if (reported + clicked) else None)
        hrs_no_momento = [o.risk_before for o in alvos if o.risk_before is not None]
        campanhas.append({
            "campanha_id": cid,
            "data": min(x.sent_at for x in alvos).strftime("%Y-%m-%d"),
            "alvos": len(alvos),
            "fechados": n_f,
            "pendentes": len(alvos) - n_f,
            "taxa_clique_pct": round(clicked / n_f * 100, 1) if n_f else None,
            "ic95_clique_pct": [round(lo * 100, 1), round(hi * 100, 1)] if n_f else None,
            "taxa_reporte_pct": round(reported / n_f * 100, 1) if n_f else None,
            "resilience_rate_pct": resiliencia,
            "tempo_mediano_ate_acao_s": round(float(np.median(tempos)), 1) if tempos else None,
            "hri_no_momento": round(sum(hrs_no_momento) / len(hrs_no_momento), 1) if hrs_no_momento else None,
        })

    return {
        "status": "OK",
        "n_colaboradores": len(com_score),
        "hrs_media_simples": round(media_simples, 1),
        "hri_ponderado_criticidade": round(hri, 1),
        "delta_ponderacao": round(hri - media_simples, 1),
        "colaboradores_sem_ativo_associado": sem_ativo,
        "distribuicao_por_banda": distribuicao,
        "serie_por_campanha": campanhas,
        "nota": (
            "Um HRI acima da média simples significa que o risco está concentrado "
            "em quem tem acesso a ativos críticos — é o sinal que a direção precisa de ver."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# A5 — HRI vs incidentes de origem humana (correlação desfasada)
# ─────────────────────────────────────────────────────────────────────────────

def a5_hri_vs_incidentes(ds: Dataset) -> Dict:
    """
    Correlaciona o HRI de um mês com os incidentes de origem humana do mês
    SEGUINTE. O desfasamento é o que dá direcionalidade defensável: o risco
    medido antecede o incidente, em vez de ser descrito depois dele.
    """
    if not ds.risk_points:
        return _insuficiente("sem histórico em risk_events", "registo do HRS ao longo do tempo")

    def chave(d: datetime) -> Tuple[int, int]:
        return (d.year, d.month)

    def seguinte(k: Tuple[int, int]) -> Tuple[int, int]:
        return (k[0] + 1, 1) if k[1] == 12 else (k[0], k[1] + 1)

    hri_mes: Dict[Tuple[int, int], float] = {}
    buckets: Dict[Tuple[int, int], List[float]] = {}
    for p in ds.risk_points:
        if p.risk_score is not None:
            buckets.setdefault(chave(p.created_at), []).append(p.risk_score)
    for k, vals in buckets.items():
        hri_mes[k] = sum(vals) / len(vals)

    inc_mes: Dict[Tuple[int, int], int] = {}
    for i in ds.incidents:
        if i.human_factor:
            k = chave(i.created_at)
            inc_mes[k] = inc_mes.get(k, 0) + 1

    pares = [(hri_mes[k], inc_mes.get(seguinte(k), 0))
             for k in sorted(hri_mes) if seguinte(k) in inc_mes or k != max(hri_mes)]
    pares = [p for p in pares if p is not None]

    n_hf = sum(1 for i in ds.incidents if i.human_factor)
    if len(pares) < MIN_N["lag_periodos"]:
        return _insuficiente(
            f"apenas {len(pares)} mês(es) emparelhado(s) HRI(t) → incidentes(t+1)",
            f"≥ {MIN_N['lag_periodos']} meses de histórico contínuo de risk_events e incidentes",
        )

    x = np.array([p[0] for p in pares], dtype=float)
    y = np.array([p[1] for p in pares], dtype=float)
    rho, p_value = stats.spearmanr(x, y)

    return {
        "status": "OK",
        "n_periodos": len(pares),
        "incidentes_origem_humana": n_hf,
        "incidentes_total": len(ds.incidents),
        "spearman_rho": round(float(rho), 3),
        "p_value": round(float(p_value), 5),
        "significativo": bool(p_value < ALPHA),
        "limitacao": (
            "A origem humana do incidente é inferida por palavra-chave no título/"
            "descrição (proxy). A tabela incidents não regista causa-raiz nem o "
            "colaborador implicado — ver lacunas de instrumentação."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# A6 — Poder estatístico
# ─────────────────────────────────────────────────────────────────────────────

def a6_poder(ds: Dataset) -> Dict:
    """Que dimensão de amostra é precisa para o estudo ter poder de conclusão?"""
    fechados = ds.engaged
    n_colab = len({o.user_id for o in fechados})
    if fechados:
        p0 = sum(o.clicked for o in fechados) / len(fechados)
    else:
        p0 = None

    p_ref = p0 if p0 and 0.02 < p0 < 0.98 else DEMO_BASE_CLICK
    origem = "observada" if p_ref is p0 else f"assumida ({DEMO_BASE_CLICK:.0%}, sem dados suficientes)"

    p1 = max(0.001, p_ref - EFEITO_ALVO_PP / 100)
    n_req = n_por_grupo(p_ref, p1)

    return {
        "status": "OK",
        "taxa_clique_baseline": round(p_ref * 100, 1),
        "origem_baseline": origem,
        "efeito_alvo_pp": EFEITO_ALVO_PP,
        "n_necessario_por_braco": n_req,
        "n_necessario_total": n_req * 2 if n_req else None,
        "n_colaboradores_atual": n_colab,
        "exposicoes_fechadas_atual": len(fechados),
        "efeito_minimo_detetavel_pp": efeito_detetavel(p_ref, max(n_colab, 1)),
        "nota": (
            f"Com α={ALPHA} e poder={POWER_TARGET:.0%}, duas proporções independentes. "
            "Um desenho pré/pós emparelhado (McNemar) precisa de menos, porque cada "
            "colaborador serve de seu próprio controlo."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Lacunas de instrumentação
# ─────────────────────────────────────────────────────────────────────────────

def lacunas_instrumentacao(ds: Dataset) -> List[str]:
    """Aponta o que falta registar para as análises passarem a ser possíveis."""
    gaps: List[str] = []
    if not any(p.event_type == "mission" for p in ds.risk_points):
        gaps.append(
            "Nenhuma missão registada em risk_events — sem exposição ao treino não "
            "há variável independente. Popular também user_missions (hoje vazia)."
        )
    if sum(1 for o in ds.observations if not o.engaged) > len(ds.observations) / 2:
        gaps.append(
            "A maioria das campanhas está por fechar: marcar os alvos sem ação como "
            "'ignored' ao fim do prazo, para os desfechos entrarem na análise."
        )
    if not ds.synthetic:
        gaps.append(
            "risk_events não tem campaign_id nem braço experimental (cohort): sem "
            "isso a ligação medição↔campanha e a alocação tratamento/controlo têm "
            "de ser inferidas por data."
        )
        gaps.append(
            "incidents não tem flag de origem humana nem colaborador implicado — "
            "a análise A5 fica limitada a correlação ao nível da organização."
        )
    if sum(1 for u in ds.users if u.criticality is None) > 0:
        gaps.append(
            "Há colaboradores sem ativo associado (users.asset_id): entram no HRI "
            "com peso neutro, o que dilui a ponderação por criticidade."
        )
    return gaps


# ─────────────────────────────────────────────────────────────────────────────
# Relatório
# ─────────────────────────────────────────────────────────────────────────────

def _linha(t: str = "") -> None:
    print(t)


def _cabecalho(t: str) -> None:
    print("\n" + "=" * 100)
    print(f"  {t}")
    print("=" * 100)


def _resultado_insuficiente(r: Dict) -> bool:
    if r.get("status") != "INSUFICIENTE":
        return False
    print(f"  [DADOS INSUFICIENTES] {r['motivo']}")
    print(f"  Necessário: {r['necessario']}")
    return True


def imprimir_relatorio(ds: Dataset, res: Dict) -> None:
    _cabecalho("ANÁLISE DE EFICÁCIA DO TREINO GAMIFICADO — SOCHAI")
    print(f"  Fonte dos dados : {ds.source}")
    print(f"  Colaboradores   : {len(ds.users)}")
    print(f"  Exposições      : {len(ds.observations)} ({len(ds.engaged)} com desfecho observado)")
    print(f"  Incidentes      : {len(ds.incidents)} "
          f"({sum(1 for i in ds.incidents if i.human_factor)} de origem humana, por proxy)")

    if ds.synthetic:
        print("\n  " + "!" * 96)
        print("  !! DADOS SINTÉTICOS — a relação treino→comportamento é imposta pelos parâmetros DEMO_*.")
        print("  !! Demonstra a sensibilidade do instrumento de medição, NÃO a eficácia da gamificação.")
        print("  " + "!" * 96)

    for aviso in ds.avisos:
        print(f"\n  [aviso] {aviso}")

    # A1
    _cabecalho("A1 · PRÉ/PÓS INTRA-SUJEITO (McNemar exato)")
    r = res["a1_pre_pos"]
    if not _resultado_insuficiente(r):
        print(f"  Pares (colaboradores com campanha antes e depois): {r['n_pares']}")
        print(f"  Taxa de cliques   pré: {r['taxa_clique_pre']}%    pós: {r['taxa_clique_pos']}%")
        print(f"  Redução absoluta : {r['reducao_absoluta_pp']} p.p.    "
              f"relativa: {r['reducao_relativa_pct']}%")
        print(f"  Melhoraram: {r['melhoraram']}   Pioraram: {r['pioraram']}   "
              f"Discordantes: {r['discordantes']}")
        t = r.get("teste", {})
        if t.get("status") == "INSUFICIENTE":
            print(f"  [teste não realizado] {t['motivo']} — necessário: {t['necessario']}")
        else:
            print(f"  {t['nome']}: p = {t['p_value']}  "
                  f"({'significativo' if t['significativo'] else 'não significativo'} a α={ALPHA})")

    # A2
    _cabecalho("A2 · DOSE-RESPOSTA (logística + bootstrap por cluster)")
    r = res["a2_dose_resposta"]
    if not _resultado_insuficiente(r):
        print(f"  {r['n_exposicoes']} exposições · {r['n_colaboradores']} colaboradores · "
              f"{r['cliques']} cliques · {r['replicas_bootstrap']} réplicas bootstrap")
        for chave, rotulo in (("or_por_missao", "por +1 missão concluída"),
                              ("or_por_10pp_score", "por +10 p.p. de score de treino")):
            o = r[chave]
            ic = f"IC95% [{o['ic95'][0]}, {o['ic95'][1]}]" if o.get("ic95") else o.get("nota", "")
            marca = "  <- efeito protetor significativo" if o.get("protetor_significativo") else ""
            print(f"  OR {rotulo:<34}: {o['odds_ratio']:>6}   {ic}{marca}")
        t = r.get("tendencia", {})
        if t.get("status") == "INSUFICIENTE":
            print(f"  [tendência não avaliada] {t['motivo']}")
        else:
            print(f"  Taxa de cliques por tercil de exposição: "
                  f"{' | '.join(f'{v}%' for v in t['taxa_clique_por_tercil'])}")
            ca = t["cochran_armitage"]
            if ca.get("status") == "OK":
                print(f"  Tendência de Cochran-Armitage: z = {ca['z']}, p = {ca['p_value']}")
        print("  Nota: OR < 1 = menos probabilidade de clicar. O IC é obtido reamostrando")
        print("        COLABORADORES, o que respeita as medições repetidas por sujeito.")

    # A3
    _cabecalho("A3 · VALIDADE PREDITIVA (corte temporal — quebra a circularidade)")
    r = res["a3_validade_preditiva"]
    if not _resultado_insuficiente(r):
        print(f"  Conjunto de validação: {r['n_validacao']} exposições futuras")
        print(f"  AUC-ROC : {r['auc_roc']}  ({r['interpretacao_auc']})")
        print(f"  Brier   : {r['brier_score']}")
        print(f"  Lift no tercil de maior risco: {r['lift_tercil_superior']}x  "
              f"({r['taxa_clique_tercil_superior_pct']}% vs {r['taxa_clique_global_pct']}% global)")
        if r["calibracao"]:
            print("\n  Calibração — o HRS corresponde ao comportamento observado?")
            print(f"  {'Banda HRS':<14}{'n':>6}{'HRS médio':>12}{'Cliques obs.':>15}")
            for c in r["calibracao"]:
                print(f"  {c['banda_hrs']:<14}{c['n']:>6}{c['hrs_medio']:>12}"
                      f"{c['taxa_clique_observada_pct']:>14}%")

    # A4
    _cabecalho("A4 · SCORE ORGANIZACIONAL (HRI ponderado pela criticidade do ativo)")
    r = res["a4_score_organizacional"]
    if not _resultado_insuficiente(r):
        print(f"  HRS média simples        : {r['hrs_media_simples']}")
        print(f"  HRI ponderado            : {r['hri_ponderado_criticidade']}  "
              f"(delta {r['delta_ponderacao']:+})")
        d = r["distribuicao_por_banda"]
        print(f"  Distribuição             : BAIXO {d['BAIXO']} · MEDIO {d['MEDIO']} · ALTO {d['ALTO']}")
        if r["colaboradores_sem_ativo_associado"]:
            print(f"  Sem ativo associado      : {r['colaboradores_sem_ativo_associado']} (peso neutro)")
        if r["serie_por_campanha"]:
            print("\n  Série por campanha:")
            print(f"  {'Data':<12}{'Alvos':>7}{'Fech.':>7}{'Clique':>9}{'Reporte':>9}"
                  f"{'Resil.':>9}{'T.mediano':>11}{'HRI':>8}")
            for c in r["serie_por_campanha"]:
                f = lambda v, s="": f"{v}{s}" if v is not None else "—"
                print(f"  {c['data']:<12}{c['alvos']:>7}{c['fechados']:>7}"
                      f"{f(c['taxa_clique_pct'],'%'):>9}{f(c['taxa_reporte_pct'],'%'):>9}"
                      f"{f(c['resilience_rate_pct'],'%'):>9}{f(c['tempo_mediano_ate_acao_s'],'s'):>11}"
                      f"{f(c['hri_no_momento']):>8}")

    # A5
    _cabecalho("A5 · HRI(t) → INCIDENTES DE ORIGEM HUMANA (t+1)")
    r = res["a5_hri_vs_incidentes"]
    if not _resultado_insuficiente(r):
        print(f"  Períodos emparelhados: {r['n_periodos']} meses")
        print(f"  Incidentes de origem humana: {r['incidentes_origem_humana']}/{r['incidentes_total']}")
        print(f"  Spearman rho = {r['spearman_rho']}, p = {r['p_value']} "
              f"({'significativo' if r['significativo'] else 'não significativo'})")
        print(f"  Limitação: {r['limitacao']}")

    # A6
    _cabecalho("A6 · PODER ESTATÍSTICO")
    r = res["a6_poder"]
    print(f"  Taxa de cliques de baseline: {r['taxa_clique_baseline']}% ({r['origem_baseline']})")
    print(f"  Para detetar uma redução de {r['efeito_alvo_pp']} p.p.: "
          f"n ≈ {r['n_necessario_por_braco']} por braço ({r['n_necessario_total']} no total)")
    print(f"  Situação atual: {r['n_colaboradores_atual']} colaboradores, "
          f"{r['exposicoes_fechadas_atual']} exposições fechadas")
    if r["efeito_minimo_detetavel_pp"]:
        print(f"  Com o n atual, só é detetável um efeito ≥ {r['efeito_minimo_detetavel_pp']} p.p.")
    print(f"  {r['nota']}")

    # Lacunas
    gaps = res["lacunas_instrumentacao"]
    if gaps:
        _cabecalho("LACUNAS DE INSTRUMENTAÇÃO — o que falta registar")
        for i, g in enumerate(gaps, 1):
            print(f"  {i}. {g}")

    _cabecalho("LEITURA DOS RESULTADOS")
    print("  A1/A2 mostram ASSOCIAÇÃO entre treino e comportamento observado.")
    print("  A3 é o que permite afirmar que o HRS MEDE risco, e não apenas que o descreve:")
    print("     o alvo é uma campanha que ainda não tinha entrado no cálculo do score.")
    print("  Sem grupo de controlo, A1 não separa o efeito do treino do efeito de")
    print("  ser repetidamente testado (Hawthorne). Alocar metade dos colaboradores a")
    print("  um braço sem treino e usar diferenças-em-diferenças resolve isso.")


# ─────────────────────────────────────────────────────────────────────────────
# Orquestração
# ─────────────────────────────────────────────────────────────────────────────

def correr_analises(ds: Dataset, b_boot: int = BOOTSTRAP_B, seed: int = 42) -> Dict:
    return {
        "gerado_em": datetime.now().isoformat(),
        "fonte": ds.source,
        "sintetico": ds.synthetic,
        "avisos": ds.avisos,
        "a1_pre_pos": a1_pre_pos(ds),
        "a2_dose_resposta": a2_dose_resposta(ds, b_boot=b_boot, seed=seed),
        "a3_validade_preditiva": a3_validade_preditiva(ds),
        "a4_score_organizacional": a4_score_organizacional(ds),
        "a5_hri_vs_incidentes": a5_hri_vs_incidentes(ds),
        "a6_poder": a6_poder(ds),
        "lacunas_instrumentacao": lacunas_instrumentacao(ds),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Análise de eficácia do treino gamificado (SOCHAI)."
    )
    parser.add_argument("--demo", action="store_true",
                        help="usa um painel sintético em vez da base de dados")
    parser.add_argument("--n-users", type=int, default=200, help="colaboradores no modo --demo")
    parser.add_argument("--n-campanhas", type=int, default=5, help="campanhas no modo --demo")
    parser.add_argument("--seed", type=int, default=42, help="semente de reprodutibilidade")
    parser.add_argument("--db", default=DB_PATH, help="caminho para a base de dados")
    parser.add_argument("--bootstrap", type=int, default=BOOTSTRAP_B,
                        help="réplicas do bootstrap por cluster")
    parser.add_argument("--json-out", default=JSON_OUT, help="ficheiro de saída JSON")
    args = parser.parse_args()

    if args.demo:
        ds = simulate_dataset(args.n_users, args.n_campanhas, args.seed)
    else:
        ds = load_from_db(args.db)

    res = correr_analises(ds, b_boot=args.bootstrap, seed=args.seed)
    imprimir_relatorio(ds, res)

    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2, default=float)
    print(f"\nRelatório completo guardado em: {os.path.basename(args.json_out)}")


if __name__ == "__main__":
    main()
