"""
L6 - SOAR Execution Engine
Security Orchestration, Automation and Response.
Determines and executes (simulated) automated response actions based on
incident severity and threat type.
"""

from datetime import datetime
from typing import Dict, List, Optional


_SEVERITY_ORDER = {"BAIXA": 1, "MEDIA": 2, "ALTA": 3, "CRITICA": 4}

# Action catalog: each entry defines when an action applies and whether it
# runs automatically (True) or requires human approval first (False).
_ACTION_CATALOG: Dict[str, Dict] = {
    "create_ticket": {
        "name": "Criar Ticket de Incidente",
        "description": "Abre ticket no sistema ITSM com todos os detalhes do incidente",
        "min_severity": "BAIXA",
        "auto_execute": True,
    },
    "block_ip": {
        "name": "Bloquear IP de Origem",
        "description": "Adiciona o IP de origem à lista negra do firewall perimetral",
        "min_severity": "MEDIA",
        "auto_execute": True,
    },
    "quarantine_email": {
        "name": "Quarentena de Email",
        "description": "Move emails maliciosos para quarentena e bloqueia remetente",
        "min_severity": "MEDIA",
        "auto_execute": True,
    },
    "collect_forensics": {
        "name": "Recolha de Evidências Forenses",
        "description": "Captura snapshot de memória, logs e artefactos do sistema afetado",
        "min_severity": "MEDIA",
        "auto_execute": True,
    },
    "update_threat_intel": {
        "name": "Atualizar Threat Intelligence",
        "description": "Propaga novos IOCs para todas as soluções de segurança",
        "min_severity": "MEDIA",
        "auto_execute": True,
    },
    "isolate_host": {
        "name": "Isolar Host da Rede",
        "description": "Coloca o host afetado em VLAN de quarentena isolada",
        "min_severity": "ALTA",
        "auto_execute": True,
    },
    "disable_account": {
        "name": "Desativar Conta de Utilizador",
        "description": "Suspende contas de utilizador comprometidas no Active Directory",
        "min_severity": "ALTA",
        "auto_execute": False,
    },
    "force_password_reset": {
        "name": "Forçar Reset de Password",
        "description": "Força reset de password para todas as contas potencialmente afetadas",
        "min_severity": "ALTA",
        "auto_execute": False,
    },
    "notify_management": {
        "name": "Notificar Gestão Sénior",
        "description": "Envia alerta imediato à gestão sénior e CISO",
        "min_severity": "CRITICA",
        "auto_execute": True,
    },
    "activate_ir_team": {
        "name": "Ativar Equipa de Resposta a Incidentes",
        "description": "Convoca equipa IR completa para gestão do incidente crítico",
        "min_severity": "CRITICA",
        "auto_execute": True,
    },
    "initiate_drp": {
        "name": "Iniciar Plano de Recuperação de Desastres",
        "description": "Ativa DRP para garantir continuidade de negócio",
        "min_severity": "CRITICA",
        "auto_execute": False,
    },
}

# Threat-type–specific extra actions
_THREAT_EXTRA: Dict[str, List[str]] = {
    "ransomware": ["emergency_backup", "activate_ir_team", "notify_management"],
    "malware": ["emergency_backup"],
    "phishing": ["user_awareness_broadcast"],
    "data_exfiltration": ["gdpr_notification_workflow"],
    "ddos": ["activate_ddos_protection", "cdn_failover"],
    "intrusion": ["revoke_all_sessions"],
    "account_compromise": ["disable_account", "force_password_reset"],
}

_EXTRA_CATALOG: Dict[str, Dict] = {
    "emergency_backup": {
        "name": "Backup de Emergência",
        "description": "Inicia backup imediato de todos os dados críticos identificados",
        "auto_execute": True,
    },
    "user_awareness_broadcast": {
        "name": "Alerta de Consciencialização",
        "description": "Envia alerta de consciencialização de phishing a todos os utilizadores",
        "auto_execute": True,
    },
    "gdpr_notification_workflow": {
        "name": "Workflow GDPR 72h",
        "description": "Inicia processo de notificação obrigatória às autoridades (GDPR Art. 33)",
        "auto_execute": False,
    },
    "activate_ddos_protection": {
        "name": "Ativar Proteção Anti-DDoS",
        "description": "Ativa scrubbing center e notifica ISP para filtros upstream",
        "auto_execute": True,
    },
    "cdn_failover": {
        "name": "Failover via CDN",
        "description": "Redireciona tráfego crítico através de CDN para garantir disponibilidade",
        "auto_execute": True,
    },
    "revoke_all_sessions": {
        "name": "Revogar Todas as Sessões",
        "description": "Revoga tokens e sessões ativas em todos os sistemas afetados",
        "auto_execute": True,
    },
    "disable_account": _ACTION_CATALOG["disable_account"],
    "force_password_reset": _ACTION_CATALOG["force_password_reset"],
    "activate_ir_team": _ACTION_CATALOG["activate_ir_team"],
    "notify_management": _ACTION_CATALOG["notify_management"],
}


class SOARExecutor:
    """Determine and execute automated SOCHAI response actions."""

    def __init__(self):
        self._log: List[Dict] = []

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def plan(self, incident_id: str, threat_type: str, severity: str) -> List[Dict]:
        """Return the list of applicable actions (auto + manual) for an incident."""
        sev_level = _SEVERITY_ORDER.get(severity.upper(), 2)
        actions = []

        # Standard catalog actions
        for action_id, meta in _ACTION_CATALOG.items():
            min_sev = _SEVERITY_ORDER.get(meta["min_severity"], 1)
            if sev_level >= min_sev:
                actions.append({
                    "action_id": action_id,
                    "name": meta["name"],
                    "description": meta["description"],
                    "auto_execute": meta["auto_execute"],
                    "status": "pending",
                })

        # Threat-specific extras
        for extra_id in _THREAT_EXTRA.get(threat_type.lower(), []):
            if extra_id in _EXTRA_CATALOG and not any(a["action_id"] == extra_id for a in actions):
                meta = _EXTRA_CATALOG[extra_id]
                actions.append({
                    "action_id": extra_id,
                    "name": meta["name"],
                    "description": meta["description"],
                    "auto_execute": meta["auto_execute"],
                    "status": "pending",
                })

        return actions

    def execute(self, incident_id: str, actions: List[Dict]) -> List[Dict]:
        """Execute all auto_execute=True actions and return results."""
        results = []
        for action in actions:
            if action.get("auto_execute"):
                result = self._run(incident_id, action)
                results.append(result)
        return results

    def execute_manual(
        self, incident_id: str, action_id: str, approved_by: str
    ) -> Dict:
        """Execute a manual action after human approval."""
        action = next(
            (a for a in (_ACTION_CATALOG | _EXTRA_CATALOG).values()
             if action_id in _ACTION_CATALOG or action_id in _EXTRA_CATALOG),
            None,
        )
        meta = _ACTION_CATALOG.get(action_id) or _EXTRA_CATALOG.get(action_id, {})
        action_dict = {
            "action_id": action_id,
            "name": meta.get("name", action_id),
            "description": meta.get("description", ""),
            "auto_execute": False,
        }
        result = self._run(incident_id, action_dict)
        result["approved_by"] = approved_by
        result["manually_triggered"] = True
        return result

    def get_log(self, incident_id: Optional[str] = None) -> List[Dict]:
        if incident_id:
            return [e for e in self._log if e.get("incident_id") == incident_id]
        return list(self._log)

    def summary(self) -> Dict:
        total = len(self._log)
        success = sum(1 for e in self._log if e.get("status") == "simulated_success")
        return {
            "total_actions": total,
            "success": success,
            "failed": total - success,
        }

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    def _run(self, incident_id: str, action: Dict) -> Dict:
        result = {
            "action_id": action["action_id"],
            "action_name": action["name"],
            "incident_id": incident_id,
            "executed_at": datetime.now().isoformat(),
            "status": "simulated_success",
            "message": f"[SIMULAÇÃO] {action['description']} — executado com sucesso",
            "auto_executed": action.get("auto_execute", True),
        }
        self._log.append(result)
        return result


# Singleton
soar_executor = SOARExecutor()
