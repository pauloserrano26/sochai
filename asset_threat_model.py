"""
Modelo de ameaça derivado do inventário real de ativos.

Lê os campos `services` e `config` de cada ativo — exatamente os mesmos que a
tab *Ativos* do dashboard mostra — e deduz:

  1. que fragilidades (vulnerabilidades) o ativo tem hoje;
  2. que ataque realista cada fragilidade permitiria;
  3. que alerta o SOCHAI receberia se esse ataque acontecesse.

O alerta resultante entra no pipeline normal L1→L6 (ML → playbook → XAI/HITL →
SOAR) e, por já vir com `asset_id`, arrasta consigo o dono do ativo para a
camada L5 (risco humano + missão de formação).

Nada aqui inventa ativos: se o inventário não tiver fragilidades, não há
cenário para gerar.
"""

from __future__ import annotations

import zlib
from typing import Dict, List, Optional

# Ordem crescente de severidade usada no resto da plataforma.
_SEVERITY_ORDER = ["BAIXA", "MEDIA", "ALTA", "CRITICA"]

# IPs de "atacante" usados nas descrições dos alertas simulados.
# Blocos reservados a documentação/teste (RFC 5737) — nunca endereços reais.
_ATTACKER_IPS = [
    "198.51.100.23", "203.0.113.47", "198.51.100.91",
    "203.0.113.150", "192.0.2.66", "198.51.100.204",
]

# Tipo de ameaça -> template de simulação de phishing adequado.
PHISHING_TRIGGER_TYPES = {
    "phishing": "credential_harvest",
    "account_compromise": "ceo_fraud",
}


def _stable_pick(seq: List, *parts) -> str:
    """Escolha determinística — o mesmo ativo/vulnerabilidade dá sempre o mesmo IP."""
    key = "|".join(str(p) for p in parts)
    return seq[zlib.crc32(key.encode("utf-8")) % len(seq)]


def _shift_severity(severity: str, steps: int) -> str:
    try:
        idx = _SEVERITY_ORDER.index((severity or "MEDIA").upper())
    except ValueError:
        idx = 1
    return _SEVERITY_ORDER[max(0, min(len(_SEVERITY_ORDER) - 1, idx + steps))]


def _adjust_for_asset(severity: str, criticality: Optional[str]) -> str:
    """A mesma fragilidade pesa mais num ativo crítico do que num periférico."""
    crit = (criticality or "MEDIO").upper()
    if crit == "CRITICO":
        return _shift_severity(severity, 1)
    if crit == "BAIXO":
        return _shift_severity(severity, -1)
    return severity


def severity_rank(severity: str) -> int:
    try:
        return _SEVERITY_ORDER.index((severity or "MEDIA").upper())
    except ValueError:
        return 1


def _vuln(
    asset: Dict,
    vuln_id: str,
    title: str,
    severity: str,
    evidence: str,
    threat_type: str,
    attack: str,
    remediation: str,
    weight: int,
    inbound: bool = True,
) -> Dict:
    """Constrói o registo de uma vulnerabilidade já contextualizada no ativo."""
    final_sev = _adjust_for_asset(severity, asset.get("criticality"))
    asset_ip = asset.get("ip_address") or "sem IP"
    return {
        "id": vuln_id,
        "asset_id": asset.get("id"),
        "asset_name": asset.get("name"),
        "title": title,
        "severity": final_sev,
        "base_severity": severity.upper(),
        "evidence": evidence,
        "threat_type": threat_type,
        "attack": attack,
        "remediation": remediation,
        "weight": weight,
        # IP de origem do alerta: um atacante externo nos ataques de entrada,
        # o próprio ativo quando o sinal parte de dentro (beacon/exfiltração).
        "source_ip": (
            _stable_pick(_ATTACKER_IPS, vuln_id, asset_ip)
            if inbound else (asset.get("ip_address") or None)
        ),
    }


# ====================================================================== #
# Regras de deteção de fragilidades
# ====================================================================== #

def _rule_unpatched(asset: Dict, cfg: Dict, services: List[Dict]) -> List[Dict]:
    if cfg.get("os_patched") is not False:
        return []
    last = cfg.get("last_patch_date") or "sem registo de patch"
    internet = bool(cfg.get("internet_facing"))
    os_name = asset.get("os_system") or "sistema"
    return [_vuln(
        asset, "VUL-PATCH", "Sistema por atualizar",
        "ALTA" if internet else "MEDIA",
        f"Último patch: {last}",
        "intrusion" if internet else "malware",
        f"Exploração de vulnerabilidade pública conhecida em {os_name} "
        f"({asset.get('name')}, {asset.get('ip_address') or 'IP desconhecido'}) — "
        f"o sistema não recebe correções de segurança desde {last}. "
        "Tentativa de execução remota de código detetada pelo IDS.",
        f"Aplicar o ciclo de patching em falta no {os_name} e repor a janela de "
        "manutenção mensal.",
        25, inbound=True,
    )]


def _rule_exposed_services(asset: Dict, cfg: Dict, services: List[Dict]) -> List[Dict]:
    out: List[Dict] = []
    exposed = [s for s in services if s.get("exposed")]
    # Só as duas primeiras — evita inundar um servidor web de findings iguais.
    for svc in exposed[:2]:
        name = svc.get("name") or "serviço"
        port = svc.get("port")
        port_str = f":{port}" if port else ""
        version = svc.get("version") or "versão não identificada"
        admin = any(k in name.lower() for k in ("mgmt", "admin", "ssh", "rdp"))
        out.append(_vuln(
            asset, f"VUL-EXPOSED-{(port or name)}",
            f"Serviço {name} exposto à internet",
            "CRITICA" if admin else "ALTA",
            f"{name}{port_str}/{svc.get('protocol') or '—'} — {version}",
            "intrusion",
            f"Varrimento e tentativas de autenticação repetidas contra o serviço "
            f"{name}{port_str} de {asset.get('name')} "
            f"({asset.get('ip_address') or 'IP desconhecido'}), exposto à internet. "
            f"Mais de 400 tentativas falhadas em 10 minutos a partir do mesmo IP.",
            f"Retirar o {name} da exposição direta (VPN ou lista branca de IPs), "
            "limitar tentativas de autenticação e ativar bloqueio automático.",
            25 if admin else 15, inbound=True,
        ))
    return out


def _rule_no_mfa(asset: Dict, cfg: Dict, services: List[Dict]) -> List[Dict]:
    if cfg.get("mfa_enabled") is not False:
        return []
    return [_vuln(
        asset, "VUL-NO-MFA", "Autenticação sem segundo fator (MFA)",
        "ALTA",
        "mfa_enabled = False",
        "account_compromise",
        f"Autenticação bem-sucedida na conta associada a {asset.get('name')} a partir "
        "de uma localização e horário fora do padrão habitual, apenas com password "
        "e sem segundo fator. Suspeita de credenciais comprometidas.",
        "Ativar MFA para todas as contas com acesso a este ativo, começando pelas "
        "contas com privilégios administrativos.",
        15, inbound=True,
    )]


def _rule_no_edr(asset: Dict, cfg: Dict, services: List[Dict]) -> List[Dict]:
    if cfg.get("av_edr_agent"):
        return []
    if (asset.get("asset_type") or "").lower() not in ("server", "workstation"):
        return []
    return [_vuln(
        asset, "VUL-NO-EDR", "Sem agente de AV/EDR instalado",
        "ALTA",
        "av_edr_agent = —",
        "malware",
        f"Processo desconhecido a estabelecer ligações periódicas para o exterior a "
        f"partir de {asset.get('name')} ({asset.get('ip_address') or 'IP desconhecido'}). "
        "O ativo não tem agente de AV/EDR, pelo que a deteção veio apenas da telemetria "
        "de rede — não há visibilidade do que está a correr no endpoint.",
        "Instalar e ativar o agente de EDR corporativo neste ativo e incluí-lo na "
        "consola central de monitorização.",
        20, inbound=False,
    )]


def _rule_no_backup(asset: Dict, cfg: Dict, services: List[Dict]) -> List[Dict]:
    if cfg.get("backup_enabled") is not False:
        return []
    return [_vuln(
        asset, "VUL-NO-BACKUP", "Sem cópias de segurança",
        "ALTA",
        "backup_enabled = False",
        "ransomware",
        f"Escrita massiva de ficheiros com extensão desconhecida em {asset.get('name')} "
        f"({asset.get('ip_address') or 'IP desconhecido'}) e eliminação de cópias sombra. "
        "Padrão compatível com cifragem por ransomware — o ativo não tem backups, "
        "pelo que a perda de dados seria definitiva.",
        "Incluir o ativo na política de backups (regra 3-2-1) e testar o restauro.",
        20, inbound=False,
    )]


def _rule_no_encryption(asset: Dict, cfg: Dict, services: List[Dict]) -> List[Dict]:
    if cfg.get("encryption_at_rest") is not False:
        return []
    if (asset.get("asset_type") or "").lower() != "server":
        return []
    return [_vuln(
        asset, "VUL-NO-ENCRYPTION", "Dados em repouso sem encriptação",
        "ALTA",
        "encryption_at_rest = False",
        "data_exfiltration",
        f"Transferência anómala de grande volume de dados a partir de {asset.get('name')} "
        f"({asset.get('ip_address') or 'IP desconhecido'}) para um destino externo, fora "
        "do horário laboral. Os dados não estão encriptados em repouso, pelo que seriam "
        "legíveis por quem os copiasse.",
        "Ativar encriptação em repouso nos volumes de dados e rever quem tem acesso "
        "de leitura ao sistema de ficheiros.",
        15, inbound=False,
    )]


def _rule_no_ips(asset: Dict, cfg: Dict, services: List[Dict]) -> List[Dict]:
    if not cfg.get("internet_facing"):
        return []
    if (asset.get("asset_type") or "").lower() not in ("router", "firewall"):
        return []
    if cfg.get("ips_enabled"):
        return []
    return [_vuln(
        asset, "VUL-NO-IPS", "Perímetro sem IPS ativo",
        "ALTA",
        "ips_enabled ausente no equipamento de perímetro",
        "ddos",
        f"Pico de tráfego de entrada em {asset.get('name')} "
        f"({asset.get('ip_address') or 'IP desconhecido'}) — volume ~40x acima do normal, "
        "com origem distribuída. O equipamento de perímetro não tem IPS ativo para "
        "absorver ou filtrar o ataque.",
        "Ativar o IPS no equipamento de perímetro e definir limites de taxa por "
        "origem, com plano de mitigação junto do operador.",
        15, inbound=True,
    )]


def _rule_no_spam_filter(asset: Dict, cfg: Dict, services: List[Dict]) -> List[Dict]:
    text = f"{asset.get('name') or ''} {' '.join(str(s.get('name')) for s in services)}".lower()
    if not any(k in text for k in ("email", "mail", "smtp", "imap")):
        return []
    if cfg.get("spam_filter"):
        return []
    return [_vuln(
        asset, "VUL-NO-SPAMFILTER", "Correio sem filtragem anti-spam/anti-phishing",
        "ALTA",
        "spam_filter não configurado",
        "phishing",
        f"Vaga de mensagens com domínio remetente semelhante ao da empresa entregue "
        f"nas caixas de correio através de {asset.get('name')}, sem filtragem "
        "anti-phishing. As mensagens pedem validação de credenciais num portal externo.",
        "Configurar filtragem anti-spam/anti-phishing no servidor de correio e impor "
        "SPF, DKIM e DMARC no domínio.",
        20, inbound=True,
    )]


# Palavras-chave -> (tipo de ameaça, severidade base, peso) para as
# fragilidades escritas à mão em `config.known_weaknesses`.
_WEAKNESS_KEYWORDS = [
    (("credenc", "fábrica", "fabrica", "admin/admin", "password"),
     "intrusion", "CRITICA", 25),
    (("sem autentica", "sem autenticação", "não autenticad", "nao autenticad"),
     "intrusion", "ALTA", 25),
    (("firmware", "desatualiz", "patch"), "intrusion", "ALTA", 20),
    (("vlan", "convidados", "segment"), "intrusion", "ALTA", 20),
    (("backup", "cópia", "copia"), "ransomware", "ALTA", 20),
]


def _rule_known_weaknesses(asset: Dict, cfg: Dict, services: List[Dict]) -> List[Dict]:
    out: List[Dict] = []
    for i, weakness in enumerate(cfg.get("known_weaknesses") or []):
        text = str(weakness)
        low = text.lower()
        threat_type, severity, weight = "other", "MEDIA", 15
        for keywords, t, s, w in _WEAKNESS_KEYWORDS:
            if any(k in low for k in keywords):
                threat_type, severity, weight = t, s, w
                break
        out.append(_vuln(
            asset, f"VUL-KNOWN-{i + 1}", "Fragilidade conhecida por corrigir",
            severity, text, threat_type,
            f"Exploração da fragilidade documentada em {asset.get('name')} "
            f"({asset.get('ip_address') or 'IP desconhecido'}): \"{text}\". "
            "O acesso obtido foi usado para alcançar outros sistemas da rede interna.",
            f"Corrigir a fragilidade registada no inventário: {text}.",
            weight, inbound=True,
        ))
    return out


_RULES = [
    _rule_unpatched,
    _rule_exposed_services,
    _rule_known_weaknesses,
    _rule_no_edr,
    _rule_no_backup,
    _rule_no_mfa,
    _rule_no_encryption,
    _rule_no_ips,
    _rule_no_spam_filter,
]


# ====================================================================== #
# API do módulo
# ====================================================================== #

def assess_asset(asset: Dict) -> List[Dict]:
    """Devolve as vulnerabilidades deduzidas de um ativo, da mais grave para a menos."""
    cfg = asset.get("config") or {}
    services = asset.get("services") or []
    found: List[Dict] = []
    for rule in _RULES:
        found.extend(rule(asset, cfg, services))
    found.sort(key=lambda v: (-severity_rank(v["severity"]), -v["weight"]))
    return found


_CRIT_RANK = {"CRITICO": 3, "ALTO": 2, "MEDIO": 1, "BAIXO": 0}


def risk_profile(asset: Dict) -> Dict:
    """Perfil de risco de um ativo: vulnerabilidades + índice de risco 0-100."""
    vulns = assess_asset(asset)
    exposure = sum(v["weight"] for v in vulns)
    # A criticidade do ativo multiplica a exposição: a mesma falha num servidor
    # crítico vale mais do que numa impressora.
    crit = (asset.get("criticality") or "MEDIO").upper()
    multiplier = {"CRITICO": 1.3, "ALTO": 1.15, "MEDIO": 1.0, "BAIXO": 0.85}.get(crit, 1.0)
    risk = min(100.0, round(exposure * multiplier, 1))
    return {
        "asset_id": asset.get("id"),
        "asset_name": asset.get("name"),
        "asset_type": asset.get("asset_type"),
        "ip_address": asset.get("ip_address"),
        "department": asset.get("department"),
        "criticality": crit,
        "owner": asset.get("owner"),
        "linked_users": asset.get("linked_users") or [],
        "risk_score": risk,
        "vulnerability_count": len(vulns),
        "top_severity": vulns[0]["severity"] if vulns else None,
        "threat_types": sorted({v["threat_type"] for v in vulns}),
        "vulnerabilities": vulns,
    }


def rank_profiles(profiles: List[Dict]) -> List[Dict]:
    return sorted(
        profiles,
        key=lambda p: (
            -p["risk_score"],
            -_CRIT_RANK.get(p["criticality"], 1),
            -p["vulnerability_count"],
        ),
    )


def select_attack_path(
    profiles: List[Dict],
    max_incidents: int,
    max_per_asset: int = 2,
) -> List[Dict]:
    """
    Escolhe as vulnerabilidades que vão dar origem a incidentes.

    Ordena por gravidade e criticidade do ativo, mas com dois ajustes que fazem
    o cenário valer como exercício:

      * **diversidade** — privilegia tipos de ameaça diferentes, para que os
        playbooks e as missões gerados cubram várias frentes em vez de repetirem
        a mesma resposta;
      * **impacto humano** — a igualdade de gravidade, um ativo com colaborador
        associado vem primeiro, e garante-se pelo menos um incidente num ativo
        com dono sempre que exista; é esse incidente que fecha o ciclo até à
        gamificação.
    """
    candidates: List[Dict] = []
    for profile in profiles:
        crit_rank = _CRIT_RANK.get(profile["criticality"], 1)
        has_owner = bool(profile.get("linked_users"))
        for order, vuln in enumerate(profile["vulnerabilities"]):
            candidates.append({
                "profile": profile,
                "vulnerability": vuln,
                "has_owner": has_owner,
                "sort_key": (
                    -severity_rank(vuln["severity"]),
                    0 if has_owner else 1,
                    -crit_rank,
                    order,
                    -vuln["weight"],
                ),
            })
    candidates.sort(key=lambda c: c["sort_key"])

    picked: List[Dict] = []
    per_asset: Dict[int, int] = {}

    def _take(candidate: Dict) -> bool:
        asset_id = candidate["profile"]["asset_id"]
        if per_asset.get(asset_id, 0) >= max_per_asset:
            return False
        per_asset[asset_id] = per_asset.get(asset_id, 0) + 1
        picked.append(candidate)
        return True

    # Primeira passagem: um candidato por tipo de ameaça, do mais grave ao menos,
    # para que os playbooks e as missões cubram frentes diferentes.
    seen_types = set()
    for c in candidates:
        if len(picked) >= max_incidents:
            break
        threat_type = c["vulnerability"]["threat_type"]
        if threat_type not in seen_types and _take(c):
            seen_types.add(threat_type)

    # Segunda passagem: preencher as vagas restantes pela ordem de gravidade.
    if len(picked) < max_incidents:
        chosen = {id(c) for c in picked}
        for c in candidates:
            if len(picked) >= max_incidents:
                break
            if id(c) not in chosen:
                _take(c)
    picked.sort(key=lambda c: c["sort_key"])

    # Garantir que o ciclo chega à camada humana, se houver como.
    if picked and not any(c["has_owner"] for c in picked):
        owned = next((c for c in candidates if c["has_owner"]), None)
        if owned:
            picked[-1] = owned

    return [
        {"profile": c["profile"], "vulnerability": c["vulnerability"]}
        for c in picked
    ]


def build_alert(profile: Dict, vuln: Dict) -> Dict:
    """Converte uma vulnerabilidade no alerta que o SOCHAI receberia (L1)."""
    return {
        "type": vuln["threat_type"],
        "description": vuln["attack"],
        "severity": vuln["severity"],
        "source_ip": vuln.get("source_ip"),
        "asset_id": profile["asset_id"],
    }


def asset_context(profile: Dict, vuln: Dict) -> str:
    """Contexto do ativo para alimentar a geração de playbook (RAG + LLM)."""
    users = ", ".join(
        u.get("full_name") or u.get("username", "") for u in profile.get("linked_users") or []
    )
    parts = [
        f"{profile['asset_name']} ({profile.get('asset_type') or 'ativo'})",
        f"IP {profile.get('ip_address') or 'desconhecido'}",
        f"criticidade {profile['criticality']}",
        f"departamento {profile.get('department') or '—'}",
        f"vulnerabilidade explorada: {vuln['title']} ({vuln['evidence']})",
        f"correção necessária: {vuln['remediation']}",
    ]
    if users:
        parts.append(f"colaboradores associados: {users}")
    return "; ".join(parts)
