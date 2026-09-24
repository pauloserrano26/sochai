"""
L2 - ML Ensemble Detection
Isolation Forest + feature-based scoring for anomaly detection.
Trains on synthetic baseline data at startup; no external training data required.
"""

import numpy as np
from datetime import datetime
from typing import Dict, Tuple, List, Optional


FEATURE_NAMES = [
    "hora_dia",
    "tem_ip_origem",
    "tem_url",
    "tem_hash",
    "comprimento_descricao",
    "nivel_severidade",
    "porta_suspeita",
    "score_tipo_ameaca",
    "fora_horario_laboral",
    "multiplos_iocs",
]

SEVERITY_MAP = {
    "CRITICA": 4, "CRITICAL": 4,
    "ALTA": 3, "HIGH": 3,
    "MEDIA": 2, "MEDIUM": 2,
    "BAIXA": 1, "LOW": 1,
}

THREAT_SCORES = {
    "ransomware": 5, "data_exfiltration": 5, "apt": 5,
    "malware": 4, "intrusion": 4, "phishing": 3,
    "brute_force": 3, "dos": 3, "ddos": 3,
    "scan": 2, "recon": 2,
}

SUSPICIOUS_PORTS = {22, 23, 445, 3389, 4444, 4445, 8080, 9999, 1337, 31337}


class SOCMLDetector:
    """Ensemble ML detector — L2 of the SOCHAI pipeline."""

    def __init__(self):
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        self._scaler = StandardScaler()
        self._iso_forest = IsolationForest(
            n_estimators=200,
            contamination=0.08,
            max_samples="auto",
            random_state=42,
        )
        self._trained = False
        self._train_on_synthetic()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def detect(self, alert_data: Dict) -> Tuple[float, bool, Dict]:
        """
        Analyse an alert and return (anomaly_score, is_anomaly, explanation).
        anomaly_score: 0-1 (1 = most anomalous).
        """
        feats = self._extract(alert_data)
        feats_scaled = self._scaler.transform(feats)

        raw_score = self._iso_forest.decision_function(feats_scaled)[0]
        # Map [-0.5, 0.5] → [0, 1]  (lower raw = more anomalous)
        anomaly_score = float(np.clip(0.5 - raw_score, 0.0, 1.0))
        is_anomaly = bool(self._iso_forest.predict(feats_scaled)[0] == -1)

        explanation = self._build_explanation(alert_data, feats[0], anomaly_score, is_anomaly)
        return anomaly_score, is_anomaly, explanation

    # ------------------------------------------------------------------ #
    # Feature engineering
    # ------------------------------------------------------------------ #

    def _extract(self, alert: Dict) -> np.ndarray:
        hour = datetime.now().hour

        has_ip = 1 if (alert.get("source_ip") or alert.get("ip")) else 0
        has_url = 1 if (alert.get("url") or "http" in str(alert).lower()) else 0
        has_hash = 1 if (alert.get("hash") or alert.get("file_hash")) else 0

        desc_len = min(len(str(alert.get("description", ""))) / 80, 10.0)

        sev_raw = str(alert.get("severity", "MEDIA")).upper()
        sev = SEVERITY_MAP.get(sev_raw, 2)

        try:
            port = int(alert.get("port", 0))
        except (TypeError, ValueError):
            port = 0
        port_sus = 1 if port in SUSPICIOUS_PORTS else 0

        ttype = str(alert.get("type", "")).lower()
        type_score = max(
            (score for key, score in THREAT_SCORES.items() if key in ttype),
            default=2,
        )

        off_hours = 1 if (hour < 7 or hour > 20) else 0

        ioc_count = sum([has_ip, has_url, has_hash])
        multi_ioc = 1 if ioc_count >= 2 else 0

        features = np.array([
            hour, has_ip, has_url, has_hash, desc_len,
            sev, port_sus, type_score, off_hours, multi_ioc,
        ], dtype=float)

        return features.reshape(1, -1)

    # ------------------------------------------------------------------ #
    # Training
    # ------------------------------------------------------------------ #

    def _train_on_synthetic(self):
        rng = np.random.default_rng(42)
        n = 1500

        # Normal: business hours, low severity, no suspicious ports
        normal = np.column_stack([
            rng.integers(8, 18, n),          # hora_dia
            rng.integers(0, 2, n),            # tem_ip_origem
            rng.integers(0, 2, n),            # tem_url
            np.zeros(n),                      # tem_hash
            rng.uniform(0.3, 3.0, n),         # comprimento_descricao
            rng.choice([1, 2], n, p=[0.6, 0.4]),  # nivel_severidade
            np.zeros(n),                      # porta_suspeita
            rng.choice([1, 2, 3], n, p=[0.5, 0.3, 0.2]),  # score_tipo_ameaca
            np.zeros(n),                      # fora_horario_laboral
            np.zeros(n),                      # multiplos_iocs
        ]).astype(float)

        X_scaled = self._scaler.fit_transform(normal)
        self._iso_forest.fit(X_scaled)
        self._trained = True

    # ------------------------------------------------------------------ #
    # Explanation
    # ------------------------------------------------------------------ #

    def _build_explanation(
        self, alert: Dict, feats: np.ndarray, score: float, is_anomaly: bool
    ) -> Dict:
        contributions = {
            name: float(val) for name, val in zip(FEATURE_NAMES, feats)
        }
        risks = self._identify_risks(feats)

        if is_anomaly and score > 0.7:
            summary = "ANOMALIA CRÍTICA — requer análise imediata"
        elif is_anomaly:
            summary = "ANOMALIA DETETADA — verificação recomendada"
        else:
            summary = "PADRÃO NORMAL — monitoramento de rotina"

        return {
            "anomaly_score": round(score, 4),
            "is_anomaly": is_anomaly,
            "decision_summary": summary,
            "confidence": self._confidence_label(score),
            "ml_method": "Isolation Forest (200 estimadores)",
            "feature_contributions": contributions,
            "risk_factors": risks,
            "recommended_action": self._recommend(score),
        }

    def _identify_risks(self, feats: np.ndarray) -> List[str]:
        risks = []
        hour, has_ip, has_url, has_hash, desc_len, sev, port_sus, type_sc, off_h, multi = feats

        if off_h:
            risks.append(f"Atividade fora do horário laboral ({int(hour)}h)")
        if port_sus:
            risks.append("Porta de rede suspeita detetada")
        if sev >= 4:
            risks.append("Severidade declarada CRÍTICA")
        elif sev >= 3:
            risks.append("Severidade declarada ALTA")
        if type_sc >= 4:
            risks.append("Tipo de ameaça de alto risco (score ≥4)")
        if multi:
            risks.append("Múltiplos IOCs presentes na alerta")
        if not risks:
            risks.append("Nenhum fator de risco crítico identificado")
        return risks

    @staticmethod
    def _confidence_label(score: float) -> str:
        if score > 0.80:
            return "Alta (>80%)"
        if score > 0.60:
            return "Média-Alta (60-80%)"
        if score > 0.40:
            return "Média (40-60%)"
        return "Baixa (<40%)"

    @staticmethod
    def _recommend(score: float) -> str:
        if score > 0.70:
            return "ESCALADA IMEDIATA — analista deve rever agora"
        if score > 0.50:
            return "REVISÃO PRIORITÁRIA — rever em 30 minutos"
        if score > 0.30:
            return "REVISÃO NORMAL — fila de revisão standard"
        return "MONITORAMENTO AUTOMÁTICO — sem intervenção humana"


# Lazy singleton — the IsolationForest is only imported/trained on first real
# use, not at module import time (training + sklearn import cost ~3s).
_ml_detector: Optional[SOCMLDetector] = None


def get_ml_detector() -> SOCMLDetector:
    global _ml_detector
    if _ml_detector is None:
        _ml_detector = SOCMLDetector()
    return _ml_detector
