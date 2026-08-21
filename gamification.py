"""
L5 - Gamification Engine
Generates training scenarios from real incidents, manages missions,
XP/levels, and the SOCHAI Risk Score for human collaborators.
"""

import json
import re
from datetime import datetime
from typing import Dict, List, Optional

from langchain_openai import ChatOpenAI
from config import config


# ------------------------------------------------------------------ #
# Constants
# ------------------------------------------------------------------ #

LEVEL_THRESHOLDS = [0, 100, 250, 500, 1000, 2000, 3500, 5000, 7500, 10000, 15000]

BADGES: Dict[str, Dict] = {
    "PRIMEIRO_PASSO": {
        "name": "Primeiro Passo", "icon": "🎯",
        "description": "Completou a primeira missão", "xp": 0,
    },
    "CAÇADOR_AMEAÇAS": {
        "name": "Caçador de Ameaças", "icon": "🔍",
        "description": "Completou 10 missões", "xp": 0,
    },
    "DEFENSOR": {
        "name": "Defensor", "icon": "🛡️",
        "description": "Pontuação perfeita em 5 missões", "xp": 0,
    },
    "RESPOSTA_RAPIDA": {
        "name": "Resposta Rápida", "icon": "⚡",
        "description": "Completou missão em menos de 3 minutos", "xp": 0,
    },
    "ESPECIALISTA_SOC": {
        "name": "Especialista SOCHAI", "icon": "🏆",
        "description": "Atingiu nível 10", "xp": 0,
    },
    "ZERO_RISCOS": {
        "name": "Zero Riscos", "icon": "🔒",
        "description": "Reduziu o Risk Score para 0", "xp": 0,
    },
    "SENTINELA": {
        "name": "Sentinela", "icon": "📡",
        "description": "Reportou o primeiro email suspeito ao SOCHAI", "xp": 0,
    },
    "OLHO_VIGILANTE": {
        "name": "Olho Vigilante", "icon": "👁️",
        "description": "Reportou 10 emails suspeitos confirmados", "xp": 0,
    },
}

# Recompensas de XP por reporte de phishing (modelo Cofense/PhishMe)
REPORT_XP = {
    "malicious": 100,   # reportou uma ameaça real -> recompensa máxima
    "simulated": 75,    # apanhou uma simulação do SOCHAI -> ótimo
    "benign": 15,       # falso alarme, mas reportar é sempre encorajado
    "pending": 10,      # ainda em triagem -> recompensa provisória
}

# Efeito comportamental de cada desfecho numa simulação de phishing
# (modelo Cofense/PhishMe: medir o que a pessoa FAZ, não o que responde)
SIM_OUTCOME = {
    "reported": {"xp": 80,  "risk": -7.0},   # reportou a simulação -> ótimo
    "ignored":  {"xp": 20,  "risk": -2.0},   # não interagiu -> aceitável
    "clicked":  {"xp": 0,   "risk": +10.0},  # clicou no link-isca -> risco sobe
    "pending":  {"xp": 0,   "risk": 0.0},
}

# Modelos de campanha de simulação (iscas sintéticas, domínios .test/.example)
SIM_TEMPLATES: Dict[str, Dict] = {
    "credential_harvest": {
        "name": "Expiração de Password Office 365",
        "difficulty": "INICIANTE",
        "sender": "no-reply@office365-secure.test",
        "subject": "A sua password expira em 24 horas — renove agora",
        "lure_url": "https://login.office365-secure.test/renew",
        "teachable_moment": (
            "Este era um email de SIMULAÇÃO. Sinais de alerta: domínio falso "
            "(office365-secure.test), urgência artificial e pedido de credenciais. "
            "A Microsoft nunca pede para renovar passwords por email. Da próxima vez, "
            "use o botão Reportar."
        ),
    },
    "fake_invoice": {
        "name": "Fatura por Pagar",
        "difficulty": "INTERMEDIO",
        "sender": "faturacao@fornecedor-global.test",
        "subject": "Fatura #INV-2024-8871 em atraso — ação necessária",
        "lure_url": "https://fornecedor-global.test/fatura/8871",
        "teachable_moment": (
            "SIMULAÇÃO. Faturas inesperadas com links são um vetor comum. "
            "Confirme sempre pelo canal habitual do fornecedor antes de clicar."
        ),
    },
    "ceo_fraud": {
        "name": "Pedido Urgente da Direção",
        "difficulty": "AVANCADO",
        "sender": "ceo@empresa-grupo.test",
        "subject": "Preciso de uma transferência urgente — confidencial",
        "lure_url": "https://empresa-grupo.test/transferencia",
        "teachable_moment": (
            "SIMULAÇÃO de fraude do CEO (BEC). Pedidos urgentes e confidenciais de "
            "transferências devem ser sempre verificados por um segundo canal."
        ),
    },
}

# Built-in scenarios available without LLM
_DEFAULT_SCENARIOS: List[Dict] = [
    {
        "id": "SC-001",
        "title": "O Email Suspeito",
        "description": (
            "Um colaborador recebeu um email de 'suporte@microsoft-helpdesk.net' "
            "a pedir que atualize as credenciais do Office 365 através de um link urgente."
        ),
        "type": "phishing",
        "difficulty": "INICIANTE",
        "xp_reward": 50,
        "questions": [
            {
                "question": "Qual é o primeiro passo ao receber este email?",
                "options": [
                    "Clicar no link para verificar se é legítimo",
                    "Reportar ao departamento de segurança imediatamente",
                    "Reencaminhar para colegas verificarem",
                    "Ignorar o email",
                ],
                "correct": 1,
                "explanation": (
                    "Nunca clique em links de emails suspeitos antes da validação "
                    "pelo SOCHAI. Reportar imediatamente é sempre o passo correto."
                ),
            },
            {
                "question": "O que revela o domínio 'microsoft-helpdesk.net'?",
                "options": [
                    "É um domínio oficial da Microsoft",
                    "É um domínio legítimo de suporte técnico",
                    "É um domínio suspeito não associado à Microsoft",
                    "Não é possível saber sem clicar no link",
                ],
                "correct": 2,
                "explanation": (
                    "A Microsoft usa exclusivamente domínios como microsoft.com. "
                    "Domínios como 'microsoft-helpdesk.net' são tentativas de phishing."
                ),
            },
        ],
    },
    {
        "id": "SC-002",
        "title": "Ficheiros Encriptados!",
        "description": (
            "Ao iniciar o computador, todos os ficheiros têm a extensão .locked "
            "e apareceu uma mensagem exigindo 2 Bitcoin para desencriptar."
        ),
        "type": "ransomware",
        "difficulty": "INTERMEDIO",
        "xp_reward": 150,
        "questions": [
            {
                "question": "Qual é a PRIMEIRA ação imediata?",
                "options": [
                    "Pagar o resgate para recuperar os ficheiros",
                    "Desligar o computador da rede imediatamente",
                    "Tentar desencriptar os ficheiros manualmente",
                    "Contactar o fornecedor do antivírus",
                ],
                "correct": 1,
                "explanation": (
                    "Isolar o sistema da rede é crítico para prevenir a propagação "
                    "do ransomware a outros sistemas partilhados."
                ),
            },
            {
                "question": "Deve pagar o resgate?",
                "options": [
                    "Sim, é a forma mais rápida de recuperar os dados",
                    "Não, nunca — isso financia criminosos e não garante recuperação",
                    "Depende do valor exigido",
                    "Apenas se não existirem backups",
                ],
                "correct": 1,
                "explanation": (
                    "O pagamento de resgates não garante a recuperação e financia "
                    "a criminalidade. A política do SOCHAI é nunca pagar sem aprovação da direção."
                ),
            },
            {
                "question": "Qual é o próximo passo após isolar o sistema?",
                "options": [
                    "Reinstalar o Windows imediatamente",
                    "Contactar a equipa SOCHAI e preservar evidências",
                    "Tentar desinstalar o antivírus",
                    "Reiniciar o computador",
                ],
                "correct": 1,
                "explanation": (
                    "A equipa SOCHAI deve ser contactada para coordenar a resposta, "
                    "e as evidências devem ser preservadas para análise forense."
                ),
            },
        ],
    },
    {
        "id": "SC-003",
        "title": "Acesso às 3h da Manhã",
        "description": (
            "O SIEM detetou um login bem-sucedido na conta de admin às 03:17h "
            "a partir de um IP de Singapura, num sistema que normalmente é acedido "
            "apenas em Portugal durante o horário laboral."
        ),
        "type": "intrusion",
        "difficulty": "AVANCADO",
        "xp_reward": 250,
        "questions": [
            {
                "question": "Como analista SOCHAI, qual é a prioridade imediata?",
                "options": [
                    "Aguardar mais evidências antes de agir",
                    "Enviar email ao utilizador perguntando se é ele",
                    "Bloquear o IP e revogar a sessão ativa imediatamente",
                    "Apenas documentar o incidente para revisão posterior",
                ],
                "correct": 2,
                "explanation": (
                    "Ação imediata é essencial: bloquear o IP e revogar sessões "
                    "minimiza o tempo de exposição. Aguardar implica mais dano potencial."
                ),
            },
            {
                "question": "Que indicador torna este evento suspeito?",
                "options": [
                    "O horário incomum e a geolocalização anómala",
                    "O facto de usar a conta de admin",
                    "O login ter sido bem-sucedido",
                    "O sistema acedido ser crítico",
                ],
                "correct": 0,
                "explanation": (
                    "A combinação de horário noturno + IP de país diferente do habitual "
                    "são indicadores clássicos de comprometimento de credenciais (ATO)."
                ),
            },
        ],
    },
    {
        "id": "SC-004",
        "title": "Pen Drive Encontrada",
        "description": (
            "Um colaborador encontrou uma pen drive no parque de estacionamento "
            "da empresa e inseriu-a no computador para ver o conteúdo."
        ),
        "type": "social_engineering",
        "difficulty": "INICIANTE",
        "xp_reward": 60,
        "questions": [
            {
                "question": "Qual é o maior risco desta ação?",
                "options": [
                    "Perder a pen drive",
                    "Executar malware plantado propositalmente na pen drive",
                    "Danificar a porta USB do computador",
                    "Não conseguir ler o conteúdo",
                ],
                "correct": 1,
                "explanation": (
                    "O ataque 'USB Drop' consiste em deixar pen drives com malware "
                    "em locais estratégicos para que funcionários as conectem. É uma técnica "
                    "de engenharia social muito eficaz."
                ),
            },
            {
                "question": "O que deve fazer o colaborador?",
                "options": [
                    "Entregar a pen drive ao departamento de TI/SOCHAI sem a conectar",
                    "Formatá-la antes de usar",
                    "Verificar o conteúdo com o antivírus instalado",
                    "Deixá-la no mesmo sítio",
                ],
                "correct": 0,
                "explanation": (
                    "A pen drive deve ser entregue ao SOCHAI/TI sem ser conectada. "
                    "O SOCHAI analisará em ambiente isolado (sandbox)."
                ),
            },
        ],
    },
    {
        "id": "SC-005",
        "title": "Password Partilhada",
        "description": (
            "Um colega pede a sua password para aceder a um sistema enquanto "
            "você está ausente, dizendo que é urgente e que o gestor autorizou."
        ),
        "type": "social_engineering",
        "difficulty": "INICIANTE",
        "xp_reward": 40,
        "questions": [
            {
                "question": "O que deve fazer?",
                "options": [
                    "Dar a password porque o gestor autorizou",
                    "Recusar e sugerir que o colega contacte o SOCHAI/TI para acesso temporário",
                    "Dar a password mas alterar depois",
                    "Pedir ao colega que espere pelo seu regresso",
                ],
                "correct": 1,
                "explanation": (
                    "Nunca partilhe passwords, mesmo que seja pedido por um colega. "
                    "O SOCHAI/TI tem procedimentos para conceder acessos temporários de forma segura."
                ),
            },
        ],
    },
]


class GamificationEngine:
    """Manages training missions, scoring, XP, and risk scores."""

    def __init__(self):
        self._scenarios: List[Dict] = list(_DEFAULT_SCENARIOS)
        self._llm = None  # lazy — created on first use

    def _get_llm(self):
        if self._llm is None:
            self._llm = ChatOpenAI(
                model="gpt-4o-mini",
                api_key=config.OPENAI_API_KEY,
                temperature=0.7,
            )
        return self._llm

    # ------------------------------------------------------------------ #
    # Scenarios
    # ------------------------------------------------------------------ #

    def get_scenarios(self, difficulty: Optional[str] = None) -> List[Dict]:
        if difficulty:
            return [s for s in self._scenarios if s["difficulty"] == difficulty.upper()]
        return list(self._scenarios)

    def get_scenario(self, scenario_id: str) -> Optional[Dict]:
        return next((s for s in self._scenarios if s["id"] == scenario_id), None)

    def generate_from_incident(self, incident_data: Dict) -> Dict:
        """
        Use LLM to create a training scenario derived from a real incident.
        Falls back to a template scenario on error.
        """
        prompt = f"""És um formador de cibersegurança. Cria um cenário de treino gamificado \
baseado neste incidente real, SEM revelar dados sensíveis ou reais.

INCIDENTE (resumo):
- Tipo: {incident_data.get('type', 'desconhecido')}
- Severidade: {incident_data.get('severity', 'MEDIA')}
- Descrição: {str(incident_data.get('description', ''))[:300]}

Cria um cenário realista e envolvente com:
- Título e descrição em contexto empresarial português
- 2-3 perguntas de múltipla escolha pedagógicas
- Explicações educativas para cada resposta

Responde APENAS em JSON válido:
{{
  "title": "título envolvente",
  "description": "descrição do cenário (2-3 frases)",
  "type": "{incident_data.get('type', 'malware')}",
  "difficulty": "INICIANTE|INTERMEDIO|AVANCADO",
  "xp_reward": 50,
  "questions": [
    {{
      "question": "pergunta?",
      "options": ["a", "b", "c", "d"],
      "correct": 0,
      "explanation": "explicação pedagógica"
    }}
  ]
}}"""

        try:
            resp = self._get_llm().invoke(prompt)
            match = re.search(r"\{.*\}", resp.content, re.DOTALL)
            if not match:
                raise ValueError("No JSON in LLM response")
            sc = json.loads(match.group())
            sc["id"] = f"SC-GEN-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            sc["generated"] = True
            sc["source_incident"] = incident_data.get("incident_id", "unknown")
            self._scenarios.append(sc)
            return sc
        except Exception as exc:
            return self._fallback_scenario(incident_data, str(exc))

    def add_scenario(self, scenario: Dict) -> Dict:
        if "id" not in scenario:
            scenario["id"] = f"SC-CUSTOM-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        self._scenarios.append(scenario)
        return scenario

    # ------------------------------------------------------------------ #
    # Scoring & Progression
    # ------------------------------------------------------------------ #

    def evaluate_mission(self, answers: List[int], scenario: Dict) -> Dict:
        """Score a completed mission attempt."""
        questions = scenario.get("questions", [])
        if not questions:
            return {"error": "Cenário sem questões"}

        correct = sum(
            1 for i, ans in enumerate(answers)
            if i < len(questions) and ans == questions[i].get("correct", -1)
        )
        total = len(questions)
        pct = correct / total * 100
        xp = int(scenario.get("xp_reward", 50) * pct / 100)

        feedback_items = []
        for i, q in enumerate(questions):
            user_ans = answers[i] if i < len(answers) else -1
            is_correct = user_ans == q.get("correct", -1)
            feedback_items.append({
                "question": q["question"],
                "your_answer": q["options"][user_ans] if 0 <= user_ans < len(q["options"]) else "—",
                "correct_answer": q["options"][q.get("correct", 0)],
                "is_correct": is_correct,
                "explanation": q.get("explanation", ""),
            })

        return {
            "correct": correct,
            "total": total,
            "score_percentage": round(pct, 1),
            "xp_earned": xp,
            "passed": pct >= 70,
            "feedback": self._feedback_message(pct),
            "detailed_feedback": feedback_items,
        }

    @staticmethod
    def calculate_level(xp: int) -> int:
        """Level N is reached when xp >= LEVEL_THRESHOLDS[N-1]."""
        level = 1
        for threshold in LEVEL_THRESHOLDS[1:]:
            if xp >= threshold:
                level += 1
            else:
                break
        return min(level, len(LEVEL_THRESHOLDS))

    @staticmethod
    def xp_to_next_level(xp: int) -> Dict:
        level = GamificationEngine.calculate_level(xp)
        max_level = len(LEVEL_THRESHOLDS)
        if level >= max_level:
            return {"current_level": level, "xp_in_level": 0, "xp_needed": 0, "progress_pct": 100}
        current_threshold = LEVEL_THRESHOLDS[level - 1]
        next_threshold = LEVEL_THRESHOLDS[level]
        xp_in_level = xp - current_threshold
        xp_span = next_threshold - current_threshold
        return {
            "current_level": level,
            "xp_in_level": xp_in_level,
            "xp_needed": xp_span,
            "progress_pct": round(xp_in_level / xp_span * 100, 1) if xp_span else 100,
        }

    @staticmethod
    def update_risk_score(
        current_score: float,
        missions_completed: int,
        score_percentage: float,
        has_security_incidents: bool,
    ) -> float:
        """
        Calculate human risk score (0-100, lower = safer).
        """
        base = 50.0
        # Reduce risk through training
        training_reduction = min(missions_completed * 2.5, 30)
        performance_reduction = score_percentage * 0.15
        # Increase risk for security incidents
        incident_penalty = 20.0 if has_security_incidents else 0.0

        score = base - training_reduction - performance_reduction + incident_penalty
        return round(max(0.0, min(100.0, score)), 1)

    def check_badges(self, user_data: Dict, mission_result: Dict, elapsed_minutes: float) -> List[str]:
        """Return list of newly earned badge IDs."""
        earned = []
        existing = set(user_data.get("badges", []))

        if "PRIMEIRO_PASSO" not in existing and user_data.get("missions_completed", 0) >= 1:
            earned.append("PRIMEIRO_PASSO")
        if "CAÇADOR_AMEAÇAS" not in existing and user_data.get("missions_completed", 0) >= 10:
            earned.append("CAÇADOR_AMEAÇAS")
        if "RESPOSTA_RAPIDA" not in existing and elapsed_minutes < 3 and mission_result.get("passed"):
            earned.append("RESPOSTA_RAPIDA")
        if "ESPECIALISTA_SOC" not in existing and user_data.get("level", 1) >= 10:
            earned.append("ESPECIALISTA_SOC")
        if "ZERO_RISCOS" not in existing and user_data.get("risk_score", 100) == 0:
            earned.append("ZERO_RISCOS")

        return earned

    # ------------------------------------------------------------------ #
    # Phishing Simulation (modelo Cofense/PhishMe) — mede comportamento real
    # ------------------------------------------------------------------ #

    @staticmethod
    def get_sim_templates() -> Dict[str, Dict]:
        return SIM_TEMPLATES

    @staticmethod
    def reward_for_outcome(outcome: str, current_risk: float) -> Dict:
        """
        Calcula o efeito de gamificação de um desfecho de simulação.
        Reportar reduz o risco; clicar aumenta-o (e gera momento formativo).
        """
        effect = SIM_OUTCOME.get(outcome, SIM_OUTCOME["pending"])
        new_risk = round(max(0.0, min(100.0, current_risk + effect["risk"])), 1)
        return {
            "xp_delta": effect["xp"],
            "risk_delta": effect["risk"],
            "new_risk_score": new_risk,
            "needs_teachable_moment": outcome == "clicked",
        }

    @staticmethod
    def resilience_rate(reported: int, clicked: int) -> Optional[float]:
        """
        Resilience rate = reportes / (reportes + cliques).
        Métrica-chave do modelo Cofense: mede a prontidão defensiva da organização.
        Devolve None se ninguém interagiu (sem cliques nem reportes).
        """
        denom = reported + clicked
        if denom == 0:
            return None
        return round(reported / denom * 100, 1)

    @staticmethod
    def campaign_metrics(targets: List[Dict]) -> Dict:
        """Agrega as métricas de uma campanha a partir dos seus alvos."""
        total = len(targets)
        counts = {"clicked": 0, "reported": 0, "ignored": 0, "pending": 0}
        times = []
        for t in targets:
            counts[t.get("outcome", "pending")] = counts.get(t.get("outcome", "pending"), 0) + 1
            if t.get("time_to_action_seconds"):
                times.append(t["time_to_action_seconds"])

        engaged = total - counts["pending"]
        click_rate = round(counts["clicked"] / total * 100, 1) if total else 0.0
        report_rate = round(counts["reported"] / total * 100, 1) if total else 0.0
        avg_time = round(sum(times) / len(times), 1) if times else None

        return {
            "total_targets": total,
            "clicked": counts["clicked"],
            "reported": counts["reported"],
            "ignored": counts["ignored"],
            "pending": counts["pending"],
            "engaged": engaged,
            "click_rate_pct": click_rate,
            "report_rate_pct": report_rate,
            "resilience_rate_pct": GamificationEngine.resilience_rate(
                counts["reported"], counts["clicked"]
            ),
            "avg_time_to_action_seconds": avg_time,
        }

    # ------------------------------------------------------------------ #
    # Phishing Report (modelo Cofense/PhishMe) — colaborador -> SOCHAI
    # ------------------------------------------------------------------ #

    @staticmethod
    def triage_report(report: Dict) -> Dict:
        """
        Triagem heurística inicial de um email reportado por um colaborador.
        Atribui um threat_score (0-100) e um veredicto provisório com base em
        sinais simples. A confirmação definitiva cabe ao analista SOCHAI (HITL).
        Não substitui a análise dos agentes LLM — apenas prioriza o reporte.
        """
        score = 0.0
        signals: List[str] = []

        sender = str(report.get("sender", "")).lower()
        subject = str(report.get("subject", "")).lower()
        body = str(report.get("body_snippet", "")).lower()
        urls = report.get("urls", []) or []

        # Sinal 1: domínio do remetente imita marca conhecida
        suspicious_brands = ["microsoft", "office365", "paypal", "bank", "banco",
                             "helpdesk", "suporte", "security", "verify"]
        if any(b in sender for b in suspicious_brands) and not sender.endswith(
            (".com", ".pt", ".org")
        ):
            score += 25
            signals.append("Remetente imita marca conhecida")
        elif "-" in sender.split("@")[-1] if "@" in sender else False:
            score += 15
            signals.append("Domínio do remetente com estrutura suspeita")

        # Sinal 2: linguagem de urgência / engenharia social
        urgency = ["urgente", "imediat", "expira", "suspens", "verifique",
                   "atualize", "confirme", "bloqueada", "última", "agora"]
        hits = sum(1 for w in urgency if w in subject or w in body)
        if hits >= 2:
            score += 25
            signals.append(f"Linguagem de urgência detetada ({hits} termos)")
        elif hits == 1:
            score += 10
            signals.append("Possível linguagem de urgência")

        # Sinal 3: presença de links
        if urls:
            score += 20
            signals.append(f"{len(urls)} link(s) presente(s) no email")
            # Links com IP literal ou encurtadores
            shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl"]
            if any(any(s in str(u).lower() for s in shorteners) for u in urls):
                score += 15
                signals.append("Link com encurtador de URL")

        # Sinal 4: anexo
        if report.get("has_attachment"):
            score += 15
            signals.append("Email contém anexo")

        score = round(min(score, 100.0), 1)

        if score >= 60:
            verdict = "malicious"
        elif score >= 30:
            verdict = "pending"   # requer revisão do analista
        else:
            verdict = "benign"

        return {
            "threat_score": score,
            "verdict": verdict,
            "signals": signals or ["Nenhum sinal de risco evidente"],
            "requires_soc_review": score >= 30,
        }

    @staticmethod
    def reward_for_report(verdict: str, current_risk: float) -> Dict:
        """
        Calcula a recompensa de gamificação por um reporte de phishing.
        Reportar comportamento seguro reduz o risco humano do colaborador.
        """
        xp = REPORT_XP.get(verdict, REPORT_XP["pending"])
        # Reportar é um comportamento defensivo -> reduz o risco humano
        risk_reduction = {
            "malicious": 8.0,
            "simulated": 6.0,
            "benign": 2.0,
            "pending": 3.0,
        }.get(verdict, 2.0)
        new_risk = round(max(0.0, current_risk - risk_reduction), 1)
        return {
            "xp_awarded": xp,
            "risk_reduction": risk_reduction,
            "new_risk_score": new_risk,
        }

    @staticmethod
    def check_report_badges(user_data: Dict, total_reports: int,
                            confirmed_reports: int) -> List[str]:
        """Medalhas específicas do programa de reporte de phishing."""
        earned = []
        existing = set(user_data.get("badges", []))
        if "SENTINELA" not in existing and total_reports >= 1:
            earned.append("SENTINELA")
        if "OLHO_VIGILANTE" not in existing and confirmed_reports >= 10:
            earned.append("OLHO_VIGILANTE")
        return earned

    # ------------------------------------------------------------------ #
    # Leaderboard
    # ------------------------------------------------------------------ #

    def leaderboard_from_users(self, users: List[Dict]) -> List[Dict]:
        """Sort users by XP descending and add rank."""
        ranked = sorted(users, key=lambda u: u.get("xp_points", 0), reverse=True)
        for i, u in enumerate(ranked):
            u["rank"] = i + 1
        return ranked

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    @staticmethod
    def _feedback_message(pct: float) -> str:
        if pct == 100:
            return "🏆 Perfeito! Domínio completo do cenário!"
        if pct >= 80:
            return "🎯 Muito bom! Excelente conhecimento de segurança."
        if pct >= 70:
            return "✅ Aprovado! Continue a praticar para melhorar."
        if pct >= 50:
            return "⚠️ Resultado razoável. Reveja os conceitos e tente novamente."
        return "❌ Necessita de mais estudo. Complete os materiais de formação."

    @staticmethod
    def _fallback_scenario(incident_data: Dict, error: str) -> Dict:
        ttype = incident_data.get("type", "malware")
        return {
            "id": f"SC-FB-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "title": f"Cenário: Incidente de {ttype.title()}",
            "description": (
                f"A sua organização detetou um incidente de segurança do tipo {ttype}. "
                "Como colaborador, tem um papel crucial na resposta inicial."
            ),
            "type": ttype,
            "difficulty": "INTERMEDIO",
            "xp_reward": 100,
            "generated": True,
            "fallback": True,
            "fallback_reason": error,
            "questions": [
                {
                    "question": "Qual é sempre o primeiro passo ao detetar um incidente de segurança?",
                    "options": [
                        "Ignorar e monitorar",
                        "Reportar ao SOCHAI imediatamente",
                        "Tentar resolver sozinho",
                        "Reiniciar o sistema",
                    ],
                    "correct": 1,
                    "explanation": "Reportar ao SOCHAI permite uma resposta coordenada e minimiza o impacto.",
                }
            ],
        }


# Singleton
gamification_engine = GamificationEngine()
