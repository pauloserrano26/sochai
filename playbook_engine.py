"""
L3 - Playbook Generation Engine (RAG + LLM)
TF-IDF retrieval over a built-in library + GPT-4o-mini generation.
No external vector store required.
"""

import json
import re
from datetime import datetime
from typing import Dict, List, Optional

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from config import config


# ------------------------------------------------------------------ #
# Built-in playbook library (RAG corpus)
# ------------------------------------------------------------------ #

_LIBRARY: List[Dict] = [
    {
        "id": "PB-001", "name": "Resposta a Malware", "threat_type": "malware",
        "tags": ["malware", "virus", "trojan", "worm", "spyware"],
        "steps": [
            "Isolar o sistema afetado da rede imediatamente",
            "Capturar imagem forense antes de qualquer alteração",
            "Analisar IOCs com VirusTotal e EDR",
            "Identificar vetor de infeção inicial",
            "Verificar outros sistemas possivelmente comprometidos",
            "Erradicar malware com ferramentas aprovadas",
            "Restaurar a partir de backup limpo se necessário",
            "Monitorar por 72h após remediação",
            "Documentar e atualizar regras de deteção",
        ],
        "priority_actions": ["Isolar sistema", "Analisar IOCs", "Notificar equipa"],
    },
    {
        "id": "PB-002", "name": "Resposta a Phishing", "threat_type": "phishing",
        "tags": ["phishing", "email", "spear-phishing", "social engineering", "credential theft"],
        "steps": [
            "Bloquear remetente e domínio malicioso no gateway de email",
            "Identificar todos os utilizadores que receberam o email",
            "Verificar cliques em links ou abertura de anexos",
            "Remover email de todas as caixas afetadas",
            "Analisar links e anexos em ambiente sandbox",
            "Verificar comprometimento de credenciais",
            "Forçar reset de passwords se comprometidas",
            "Notificar utilizadores afetados com orientações",
            "Reportar domínio ao serviço anti-abuso",
        ],
        "priority_actions": ["Bloquear domínio", "Identificar afetados", "Reset passwords"],
    },
    {
        "id": "PB-003", "name": "Resposta a Ransomware", "threat_type": "ransomware",
        "tags": ["ransomware", "encryption", "extortion", "data loss", "crypto"],
        "steps": [
            "ISOLAR IMEDIATAMENTE todos os sistemas da rede",
            "Desligar conexões de rede para prevenir propagação",
            "Identificar família e variante do ransomware",
            "Verificar disponibilidade e integridade de backups",
            "Contactar CERT nacional e autoridades",
            "NÃO pagar resgate sem autorização da direção",
            "Recuperar a partir de backups verificados",
            "Analisar o vetor de infeção e reparar",
            "Implementar proteções adicionais antes de reconectar",
        ],
        "priority_actions": ["ISOLAR REDE", "Verificar backups", "Contactar CERT"],
    },
    {
        "id": "PB-004", "name": "Resposta a Intrusão", "threat_type": "intrusion",
        "tags": ["intrusion", "unauthorized access", "brute force", "exploitation", "lateral movement"],
        "steps": [
            "Bloquear IP de origem no firewall imediatamente",
            "Revogar todas as sessões ativas suspeitas",
            "Analisar logs de autenticação detalhadamente",
            "Verificar privilégios e acessos modificados",
            "Analisar comandos e ações executadas",
            "Identificar dados potencialmente exfiltrados",
            "Reparar vulnerabilidades exploradas",
            "Implementar MFA se não existente",
            "Rever e auditar todos os acessos e privilégios",
        ],
        "priority_actions": ["Bloquear IP", "Revogar sessões", "Analisar logs"],
    },
    {
        "id": "PB-005", "name": "Resposta a DDoS", "threat_type": "ddos",
        "tags": ["ddos", "dos", "denial of service", "traffic flood", "availability", "botnet"],
        "steps": [
            "Ativar modo de proteção DDoS no ISP ou CDN",
            "Analisar tipo de ataque (volumétrico, protocolo, aplicação)",
            "Implementar rate limiting e blackholing dos IPs atacantes",
            "Ativar scrubbing center se disponível",
            "Contactar ISP para filtros upstream",
            "Manter serviços críticos via failover e CDN",
            "Monitorar e documentar o ataque em tempo real",
            "Comunicar impactos aos stakeholders",
            "Rever e melhorar capacidades anti-DDoS após incidente",
        ],
        "priority_actions": ["Ativar DDoS protection", "Contactar ISP", "Failover críticos"],
    },
    {
        "id": "PB-006", "name": "Exfiltração de Dados", "threat_type": "data_exfiltration",
        "tags": ["data breach", "sensitive data", "GDPR", "leakage", "insider threat", "DLP"],
        "steps": [
            "Identificar e bloquear os canais de exfiltração",
            "Determinar quais dados foram expostos e volume",
            "Preservar todas as evidências forenses",
            "Notificar DPO (Data Protection Officer) imediatamente",
            "Avaliar obrigações legais de notificação (GDPR — 72h)",
            "Notificar autoridades de proteção de dados se exigido",
            "Comunicar aos indivíduos afetados conforme legislação",
            "Revogar acessos comprometidos",
            "Implementar controlos DLP adicionais",
        ],
        "priority_actions": ["Bloquear exfiltração", "Notificar DPO", "Avaliar GDPR"],
    },
    {
        "id": "PB-007", "name": "Comprometimento de Conta", "threat_type": "account_compromise",
        "tags": ["account takeover", "credential compromise", "ATO", "password", "MFA bypass"],
        "steps": [
            "Desativar a conta comprometida imediatamente",
            "Revogar todos os tokens e sessões ativas",
            "Analisar atividade recente da conta (logs)",
            "Verificar alterações feitas com a conta comprometida",
            "Identificar método de comprometimento",
            "Notificar o utilizador e fazer reset de credenciais",
            "Habilitar MFA reforçado na conta",
            "Rever e reverter alterações não autorizadas",
            "Verificar outras contas que possam ter sido afetadas",
        ],
        "priority_actions": ["Desativar conta", "Revogar tokens", "Analisar atividade"],
    },
]


class PlaybookEngine:
    """RAG-based playbook retrieval and LLM-based generation."""

    def __init__(self):
        self._library = _LIBRARY
        self._vectorizer = TfidfVectorizer(analyzer="word", ngram_range=(1, 2))
        self._matrix = None
        self._build_index()
        self._llm = None  # lazy — created on first use

    def _get_llm(self):
        if self._llm is None:
            from langchain_openai import ChatOpenAI
            self._llm = ChatOpenAI(
                model="gpt-4o-mini",
                api_key=config.OPENAI_API_KEY,
                temperature=0.3,
            )
        return self._llm

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def retrieve(self, query: str, top_k: int = 2) -> List[Dict]:
        """Return the top-k most relevant built-in playbooks for a query."""
        q_vec = self._vectorizer.transform([query])
        sims = cosine_similarity(q_vec, self._matrix)[0]
        top_idx = np.argsort(sims)[-top_k:][::-1]
        return [self._library[i] for i in top_idx if sims[i] > 0.01]

    def generate(
        self,
        incident_description: str,
        threat_type: str,
        severity: str,
        asset_context: Optional[str] = None,
    ) -> Dict:
        """
        Generate a custom playbook for the incident using RAG + LLM.
        Falls back to the best matching built-in playbook on error.
        """
        query = f"{incident_description} {threat_type}"
        relevant = self.retrieve(query)

        context_blocks = []
        for pb in relevant:
            steps_text = "\n".join(f"  - {s}" for s in pb["steps"])
            context_blocks.append(f"Playbook '{pb['name']}' [{pb['id']}]:\n{steps_text}")
        context = "\n\n".join(context_blocks)

        asset_section = f"\nCONTEXTO DO ATIVO AFETADO: {asset_context}" if asset_context else ""

        prompt = f"""És um especialista SOCHAI. Com base nos playbooks de referência e no incidente específico, \
gera um playbook customizado e detalhado.

INCIDENTE: {incident_description}
TIPO DE AMEAÇA: {threat_type}
SEVERIDADE: {severity}{asset_section}

PLAYBOOKS DE REFERÊNCIA:
{context}

Gera um playbook adaptado com 8-10 passos específicos para este incidente.
Inclui ações de prioridade imediata e um plano de contenção.

Responde APENAS em JSON válido com esta estrutura:
{{
  "name": "nome descritivo do playbook",
  "steps": ["passo 1...", "passo 2...", "..."],
  "priority_actions": ["ação crítica 1", "ação crítica 2", "ação crítica 3"],
  "estimated_time": "tempo estimado para resolução",
  "escalation_criteria": "quando escalar para gestão sénior"
}}"""

        try:
            resp = self._get_llm().invoke(prompt)
            raw = resp.content

            # Extract JSON block
            match = re.search(r"\{.*\}", raw, re.DOTALL)
            if match:
                pb_data = json.loads(match.group())
            else:
                raise ValueError("No JSON found in LLM response")

            pb_data.update({
                "id": f"PB-GEN-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "threat_type": threat_type,
                "severity": severity,
                "retrieved_references": [pb["id"] for pb in relevant],
                "generated": True,
                "generated_at": datetime.now().isoformat(),
            })
            return pb_data

        except Exception as exc:
            # Fallback: return best matching built-in
            if relevant:
                pb = dict(relevant[0])
                pb.update({"generated": False, "fallback_reason": str(exc)})
                return pb
            return {
                "id": "PB-FALLBACK",
                "name": f"Playbook Genérico — {threat_type}",
                "steps": [
                    "1. Isolar o sistema/recurso afetado",
                    "2. Notificar a equipa SOCHAI",
                    "3. Recolher logs e evidências",
                    "4. Analisar IOCs com ferramentas disponíveis",
                    "5. Aplicar medidas de contenção",
                    "6. Erradicar a ameaça",
                    "7. Recuperar para estado normal",
                    "8. Documentar o incidente",
                ],
                "priority_actions": ["Isolar sistema", "Notificar SOCHAI"],
                "generated": False,
                "fallback_reason": str(exc),
            }

    def get_library(self) -> List[Dict]:
        return self._library

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    def _build_index(self):
        corpus = []
        for pb in self._library:
            text = (
                f"{pb['name']} {pb['threat_type']} "
                + " ".join(pb["tags"])
                + " "
                + " ".join(pb["steps"])
            )
            corpus.append(text)
        self._matrix = self._vectorizer.fit_transform(corpus)


# Singleton
playbook_engine = PlaybookEngine()
