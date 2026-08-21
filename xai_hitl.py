"""
L4 - Explainable AI + Human-in-the-Loop
Generates analyst-readable explanations for ML decisions and manages
the human review queue (HITL workflow).
"""

from datetime import datetime
from typing import Dict, List, Optional


FEATURE_DESCRIPTIONS = {
    "hora_dia": lambda v: (
        f"Atividade às {int(v)}h — {'FORA do horário laboral' if v < 7 or v > 20 else 'dentro do horário normal'}"
    ),
    "tem_ip_origem": lambda v: "IP de origem presente na alerta" if v else "Sem IP de origem identificado",
    "tem_url": lambda v: "URL suspeita identificada" if v else "Sem URL na alerta",
    "tem_hash": lambda v: "Hash de ficheiro presente para análise" if v else "Sem hash de ficheiro",
    "comprimento_descricao": lambda v: (
        f"Descrição {'muito detalhada' if v > 6 else 'moderada' if v > 2 else 'breve'} (score {v:.1f})"
    ),
    "nivel_severidade": lambda v: (
        f"Severidade declarada: {['', 'Baixa', 'Média', 'Alta', 'Crítica'][min(int(v), 4)]}"
    ),
    "porta_suspeita": lambda v: "Porta de rede de alto risco detetada" if v else "Portas normais",
    "score_tipo_ameaca": lambda v: f"Risco do tipo de ameaça: {int(v)}/5",
    "fora_horario_laboral": lambda v: "Atividade FORA do horário laboral" if v else "Horário laboral normal",
    "multiplos_iocs": lambda v: "Múltiplos IOCs presentes (IP + URL + Hash)" if v else "IOC único",
}


class XAIExplainer:
    """Generate human-readable explanations from ML detection output."""

    def explain(
        self,
        alert_data: Dict,
        ml_result: Dict,
    ) -> Dict:
        """
        Build a complete XAI report from an alert and its ML result.
        """
        score = ml_result.get("anomaly_score", 0.0)
        is_anomaly = ml_result.get("is_anomaly", False)
        features = ml_result.get("feature_contributions", {})
        risks = ml_result.get("risk_factors", [])

        factor_list = self._build_factors(features)
        decision_path = self._build_decision_path(alert_data, score, features)

        return {
            "decision_summary": ml_result.get("decision_summary", ""),
            "anomaly_score": round(score, 4),
            "confidence": ml_result.get("confidence", "N/A"),
            "top_contributing_factors": factor_list,
            "risk_factors": risks,
            "decision_path": decision_path,
            "human_readable_summary": self._narrative(alert_data, score, risks),
            "recommended_action": ml_result.get("recommended_action", ""),
            "data_completeness": self._completeness(alert_data),
            "requires_hitl": score > 0.50 or is_anomaly,
            "hitl_sla_minutes": 15 if score > 0.70 else 30 if score > 0.50 else 60,
        }

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _build_factors(self, features: Dict) -> List[Dict]:
        result = []
        for name, val in sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)[:6]:
            desc_fn = FEATURE_DESCRIPTIONS.get(name)
            description = desc_fn(val) if desc_fn else f"Valor: {val:.2f}"
            impact = "alto" if abs(val) >= 3 else "médio" if abs(val) >= 1 else "baixo"
            result.append({
                "feature": name,
                "value": round(float(val), 2),
                "impact": impact,
                "description": description,
            })
        return result

    def _build_decision_path(self, alert: Dict, score: float, features: Dict) -> List[str]:
        path = ["Alerta recebida e pré-processada pelo sistema de telemetria (L1)"]
        path.append("Extração de features e análise pelo modelo Isolation Forest (L2)")
        path.append(f"Score de anomalia calculado: {score:.3f}")

        if features.get("fora_horario_laboral", 0):
            path.append("→ Fator de risco: atividade fora do horário laboral")
        if features.get("porta_suspeita", 0):
            path.append("→ Fator de risco: porta de rede suspeita")
        if features.get("nivel_severidade", 0) >= 3:
            path.append("→ Fator de risco: severidade alta ou crítica")

        if score > 0.70:
            path.append("→ Score excede limiar crítico (>0.70) → HITL OBRIGATÓRIO")
        elif score > 0.50:
            path.append("→ Score excede limiar de revisão (>0.50) → HITL recomendado")
        else:
            path.append("→ Score dentro de parâmetros normais → pipeline automático")

        path.append("Encaminhado para análise LLM multi-agente (L3)")
        return path

    def _narrative(self, alert: Dict, score: float, risks: List[str]) -> str:
        atype = alert.get("type", "desconhecido")
        sev = alert.get("severity", "MEDIA")
        src = alert.get("source_ip", "desconhecido")

        text = (
            f"O sistema detetou uma alerta de tipo '{atype}' "
            f"com IP de origem {src} e severidade {sev}. "
            f"O modelo ML atribuiu um score de anomalia de {score:.2f}/1.00. "
        )
        if risks and risks[0] != "Nenhum fator de risco crítico identificado":
            text += f"Principais fatores: {'; '.join(risks[:3])}. "

        if score > 0.70:
            text += "REVISÃO IMEDIATA pelo analista é obrigatória."
        elif score > 0.50:
            text += "Revisão humana recomendada para confirmação."
        else:
            text += "Monitoramento automático é suficiente."

        return text

    @staticmethod
    def _completeness(alert: Dict) -> str:
        fields = ["source_ip", "type", "severity", "description"]
        present = sum(1 for f in fields if alert.get(f))
        return f"{present / len(fields) * 100:.0f}%"


class HITLManager:
    """Manage the human analyst review queue (Human-in-the-Loop)."""

    def __init__(self):
        self._pending: Dict[str, Dict] = {}
        self._completed: Dict[str, Dict] = {}

    # ------------------------------------------------------------------ #
    # Queue management
    # ------------------------------------------------------------------ #

    def request_review(
        self,
        incident_id: str,
        alert_data: Dict,
        xai_report: Dict,
        ml_result: Dict,
    ) -> Dict:
        sla = xai_report.get("hitl_sla_minutes", 30)
        review = {
            "incident_id": incident_id,
            "status": "pending_review",
            "requested_at": datetime.now().isoformat(),
            "alert_type": alert_data.get("type", "unknown"),
            "severity": alert_data.get("severity", "MEDIA"),
            "source_ip": alert_data.get("source_ip", "N/A"),
            "anomaly_score": ml_result.get("anomaly_score", 0),
            "decision_summary": xai_report.get("decision_summary", ""),
            "risk_factors": xai_report.get("risk_factors", []),
            "recommended_action": xai_report.get("recommended_action", ""),
            "sla_minutes": sla,
            "xai_report": xai_report,
        }
        self._pending[incident_id] = review
        return review

    def submit_review(
        self,
        incident_id: str,
        analyst_username: str,
        decision: str,
        notes: str = "",
    ) -> Dict:
        """
        decision: 'VERDADEIRO_POSITIVO' | 'FALSO_POSITIVO' | 'ESCALAR'
        """
        review = self._pending.pop(incident_id, None)
        if review is None:
            return {"error": f"Review não encontrada para {incident_id}"}

        now = datetime.now()
        try:
            started = datetime.fromisoformat(review["requested_at"])
            review_time = round((now - started).total_seconds() / 60, 1)
        except Exception:
            review_time = 0.0

        review.update({
            "status": "reviewed",
            "analyst_username": analyst_username,
            "decision": decision,
            "analyst_notes": notes,
            "reviewed_at": now.isoformat(),
            "review_time_minutes": review_time,
            "met_sla": review_time <= review.get("sla_minutes", 30),
        })
        self._completed[incident_id] = review
        return review

    def get_pending(self) -> List[Dict]:
        return list(self._pending.values())

    def get_completed(self) -> List[Dict]:
        return list(self._completed.values())

    def stats(self) -> Dict:
        completed = list(self._completed.values())
        n = len(completed)
        if n == 0:
            return {
                "total_reviewed": 0,
                "avg_review_time_min": 0,
                "sla_compliance_pct": 0,
                "pending_count": len(self._pending),
            }
        met_sla = sum(1 for r in completed if r.get("met_sla", False))
        avg_time = sum(r.get("review_time_minutes", 0) for r in completed) / n
        return {
            "total_reviewed": n,
            "avg_review_time_min": round(avg_time, 1),
            "sla_compliance_pct": round(met_sla / n * 100, 1),
            "pending_count": len(self._pending),
        }


# Singletons
xai_explainer = XAIExplainer()
hitl_manager = HITLManager()
