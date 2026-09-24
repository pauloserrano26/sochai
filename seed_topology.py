"""
seed_topology.py — Preenche a topologia de rede (relações entre ativos),
associa colaboradores aos seus ativos, e atribui serviços/configurações
realistas a cada ativo (para que os incidentes gerados façam sentido face
ao que cada ativo expõe). Idempotente — corre via API, sem apagar dados.

Uso: python seed_topology.py
A API (api_main.py) tem de estar em execução.
"""

import sys
import requests

API = "http://localhost:8000"

ASSET_FIELDS = (
    "name", "asset_type", "ip_address", "mac_address", "hostname", "owner",
    "department", "criticality", "os_system", "location", "description", "tags",
)


def _get(path, **kw):
    r = requests.get(f"{API}{path}", timeout=10, **kw)
    r.raise_for_status()
    return r.json()


def _put_asset(asset_id, base, services=None, config=None, owner=None):
    payload = {k: base.get(k) for k in ASSET_FIELDS}
    if owner is not None:
        payload["owner"] = owner
    payload["services"] = services if services is not None else base.get("services") or []
    payload["config"] = config if config is not None else base.get("config") or {}
    r = requests.put(f"{API}/api/assets/{asset_id}", json=payload, timeout=10)
    r.raise_for_status()
    return r.json()


def _put_user(user_id, base, asset_id):
    payload = {
        "username": base["username"], "email": base.get("email"),
        "full_name": base.get("full_name"), "role": base.get("role", "employee"),
        "department": base.get("department"), "asset_id": asset_id,
    }
    r = requests.put(f"{API}/api/users/{user_id}", json=payload, timeout=10)
    r.raise_for_status()
    return r.json()


# ====================================================================== #
# 1. Serviços + configuração de segurança realistas, por nome de ativo
# ====================================================================== #

def _svc(name, port, protocol, version=None, exposed=False):
    d = {"name": name, "port": port, "protocol": protocol, "exposed": exposed}
    if version:
        d["version"] = version
    return d


SERVICES = {
    "Servidor Web Principal": (
        [_svc("HTTPS", 443, "tcp", "nginx 1.24.0", True),
         _svc("HTTP", 80, "tcp", "nginx 1.24.0 (redirect → 443)", True),
         _svc("SSH", 22, "tcp", "OpenSSH 9.3", False)],
        {"os_patched": True, "last_patch_date": "2026-09-10", "av_edr_agent": "CrowdStrike Falcon",
         "mfa_enabled": True, "internet_facing": True, "backup_enabled": True,
         "encryption_at_rest": True},
    ),
    "Firewall Perimetral": (
        [_svc("IPSec VPN", 500, "udp", "FortiOS 7.4", True),
         _svc("IPSec NAT-T", 4500, "udp", "FortiOS 7.4", True),
         _svc("HTTPS (mgmt)", 443, "tcp", "FortiOS 7.4", False)],
        {"os_patched": True, "last_patch_date": "2026-09-15", "av_edr_agent": None,
         "mfa_enabled": True, "internet_facing": True, "backup_enabled": True,
         "encryption_at_rest": False, "ips_enabled": True, "firewall_rules_count": 148},
    ),
    "Router ISP Principal": (
        [_svc("WAN uplink", 0, "n/a", "Cisco IOS 15.7", True),
         _svc("SNMP", 161, "udp", None, False)],
        {"os_patched": False, "last_patch_date": "2025-06-02", "av_edr_agent": None,
         "mfa_enabled": False, "internet_facing": True, "backup_enabled": False,
         "encryption_at_rest": False,
         "known_weaknesses": ["Firmware desatualizado — equipamento gerido pelo ISP"]},
    ),
    "Switch Core": (
        [_svc("SNMP", 161, "udp"), _svc("SSH (mgmt)", 22, "tcp", "Cisco IOS 16.9", False)],
        {"os_patched": True, "last_patch_date": "2026-08-22", "av_edr_agent": None,
         "mfa_enabled": False, "internet_facing": False, "backup_enabled": True,
         "encryption_at_rest": False},
    ),
    "Switch Core L3": (
        [_svc("SNMP", 161, "udp"), _svc("SSH (mgmt)", 22, "tcp", "Cisco IOS 16.9", False)],
        {"os_patched": True, "last_patch_date": "2026-08-22", "av_edr_agent": None,
         "mfa_enabled": False, "internet_facing": False, "backup_enabled": True,
         "encryption_at_rest": False, "notes": "Par redundante (HA/stack) do Switch Core"},
    ),
    "Switch Acesso – Piso 1": (
        [_svc("SNMP", 161, "udp"), _svc("SSH (mgmt)", 22, "tcp", "Cisco IOS 16.9", False)],
        {"os_patched": True, "last_patch_date": "2026-07-30", "av_edr_agent": None,
         "mfa_enabled": False, "internet_facing": False, "backup_enabled": True,
         "encryption_at_rest": False},
    ),
    "Access Point Wi-Fi": (
        [_svc("SSID Corporativo", 0, "802.11", "WPA2-Enterprise", False),
         _svc("SSID Convidados", 0, "802.11", "WPA2-PSK", False),
         _svc("HTTPS (mgmt)", 443, "tcp", "UniFi OS 3.2", False)],
        {"os_patched": True, "last_patch_date": "2026-08-05", "av_edr_agent": None,
         "mfa_enabled": False, "internet_facing": False, "backup_enabled": False,
         "encryption_at_rest": False,
         "known_weaknesses": ["Rede 'Convidados' partilha VLAN com a rede interna"]},
    ),
    "Servidor de Email": (
        [_svc("SMTP", 25, "tcp", "Postfix 3.8", True),
         _svc("IMAP", 993, "tcp", "Dovecot 2.3", True),
         _svc("Webmail HTTPS", 443, "tcp", "Roundcube 1.6", True)],
        {"os_patched": True, "last_patch_date": "2026-09-05", "av_edr_agent": "CrowdStrike Falcon",
         "mfa_enabled": True, "internet_facing": True, "backup_enabled": True,
         "encryption_at_rest": True, "spam_filter": "SpamAssassin"},
    ),
    "Servidor de Ficheiros (NAS)": (
        [_svc("SMB", 445, "tcp", "Samba 4.18", False),
         _svc("NFS", 2049, "tcp", None, False),
         _svc("HTTPS (admin)", 443, "tcp", "Synology DSM 7.2", False)],
        {"os_patched": False, "last_patch_date": "2025-12-01", "av_edr_agent": None,
         "mfa_enabled": False, "internet_facing": False, "backup_enabled": True,
         "encryption_at_rest": True,
         "known_weaknesses": ["Patch de segurança do DSM em atraso há vários meses"]},
    ),
    "Servidor Web / Intranet": (
        [_svc("HTTP", 80, "tcp", "Apache 2.4", False),
         _svc("HTTPS", 443, "tcp", "Apache 2.4", False),
         _svc("SSH", 22, "tcp", "OpenSSH 9.3", False)],
        {"os_patched": True, "last_patch_date": "2026-08-28", "av_edr_agent": "CrowdStrike Falcon",
         "mfa_enabled": False, "internet_facing": False, "backup_enabled": True,
         "encryption_at_rest": False},
    ),
    "Servidor de Backups": (
        [_svc("SSH", 22, "tcp", "OpenSSH 9.3", False), _svc("rsync", 873, "tcp", None, False)],
        {"os_patched": True, "last_patch_date": "2026-09-01", "av_edr_agent": "CrowdStrike Falcon",
         "mfa_enabled": True, "internet_facing": False, "backup_enabled": True,
         "encryption_at_rest": True},
    ),
    "Impressora Multifunções": (
        [_svc("HTTP (admin)", 80, "tcp", None, False), _svc("RAW print", 9100, "tcp", None, False)],
        {"os_patched": False, "last_patch_date": None, "av_edr_agent": None,
         "mfa_enabled": False, "internet_facing": False, "backup_enabled": False,
         "encryption_at_rest": False,
         "known_weaknesses": ["Interface de administração web sem autenticação",
                               "Firmware nunca atualizado desde a instalação"]},
    ),
    "Câmara IP – Entrada": (
        [_svc("RTSP", 554, "tcp", None, False), _svc("HTTP (admin)", 80, "tcp", None, False)],
        {"os_patched": False, "last_patch_date": None, "av_edr_agent": None,
         "mfa_enabled": False, "internet_facing": False, "backup_enabled": False,
         "encryption_at_rest": False,
         "known_weaknesses": ["Credenciais de fábrica (admin/admin) nunca alteradas"]},
    ),
    "Câmara IP – Sala de Servidores": (
        [_svc("RTSP (ONVIF)", 554, "tcp", None, False), _svc("HTTPS (admin)", 443, "tcp", None, False)],
        {"os_patched": True, "last_patch_date": "2026-07-15", "av_edr_agent": None,
         "mfa_enabled": False, "internet_facing": False, "backup_enabled": False,
         "encryption_at_rest": False},
    ),
}

# Workstations / laptops: (services, config) por nome — os restantes (não
# listados aqui) recebem o perfil DEFAULT_WORKSTATION mais abaixo.
_RDP_ON = _svc("RDP", 3389, "tcp", None, False)
_SMB = _svc("SMB", 445, "tcp", None, False)
_VPN = _svc("VPN Client", 0, "n/a", "IPSec", False)

SERVICES.update({
    "Portátil Diretor Geral": (
        [_VPN, _SMB],
        {"os_patched": True, "last_patch_date": "2026-09-12", "av_edr_agent": "CrowdStrike Falcon",
         "mfa_enabled": True, "internet_facing": False, "backup_enabled": True,
         "encryption_at_rest": True,
         "known_weaknesses": ["Alvo preferencial de phishing direcionado (CEO fraud)"]},
    ),
    "Portátil Diretora Financeira": (
        [_VPN, _SMB],
        {"os_patched": True, "last_patch_date": "2026-09-12", "av_edr_agent": "CrowdStrike Falcon",
         "mfa_enabled": True, "internet_facing": False, "backup_enabled": True,
         "encryption_at_rest": True,
         "known_weaknesses": ["Acesso ao sistema de pagamentos — alvo de fraude BEC"]},
    ),
    "Workstation TI – Administrador": (
        [_RDP_ON, _SMB, _svc("SSH", 22, "tcp", None, False)],
        {"os_patched": True, "last_patch_date": "2026-09-08", "av_edr_agent": "CrowdStrike Falcon",
         "mfa_enabled": True, "internet_facing": False, "backup_enabled": True,
         "encryption_at_rest": True,
         "known_weaknesses": ["RDP ativo para administração remota — superfície de ataque para brute-force"]},
    ),
    "Workstation TI – Técnico": (
        [_RDP_ON, _SMB],
        {"os_patched": True, "last_patch_date": "2026-08-18", "av_edr_agent": "Windows Defender",
         "mfa_enabled": False, "internet_facing": False, "backup_enabled": True,
         "encryption_at_rest": False},
    ),
})

DEFAULT_WORKSTATION = (
    [_SMB],
    {"os_patched": True, "last_patch_date": "2026-08-01", "av_edr_agent": "Windows Defender",
     "mfa_enabled": False, "internet_facing": False, "backup_enabled": True,
     "encryption_at_rest": False},
)
# Perfil "laggard" (mais fraco) para dar variedade/realismo — atribuído a
# alguns postos de menor criticidade.
WEAK_WORKSTATION = (
    [_SMB],
    {"os_patched": False, "last_patch_date": "2025-10-14", "av_edr_agent": "Windows Defender",
     "mfa_enabled": False, "internet_facing": False, "backup_enabled": False,
     "encryption_at_rest": False,
     "known_weaknesses": ["Atualizações de segurança em atraso"]},
)
WEAK_WORKSTATIONS = {
    "Workstation Comercial-04", "Workstation Comercial-05",
    "Workstation Operações-03", "Workstation Operações-04",
    "Workstation Marketing-02",
}


# ====================================================================== #
# 2. Topologia de rede (relações entre ativos)
# ====================================================================== #
# (origem, destino, tipo, protocolo, porta, zona, descrição)
RELATIONS = [
    ("Router ISP Principal", "Firewall Perimetral", "routes_to", "IP", None, "WAN",
     "Ligação de borda à internet"),
    ("Firewall Perimetral", "Switch Core", "connected_to", None, None, "LAN",
     "Trunk LAN interna"),
    ("Switch Core", "Switch Core L3", "connected_to", None, None, "Sala de Servidores",
     "Stack/HA entre os dois núcleos redundantes"),
    ("Switch Core", "Switch Acesso – Piso 1", "connected_to", None, None, "LAN",
     "Uplink para o piso 1"),
    ("Switch Core", "Servidor Web Principal", "hosted_on", None, None, "Sala de Servidores", None),
    ("Switch Core", "Servidor de Email", "hosted_on", None, None, "Sala de Servidores", None),
    ("Switch Core", "Servidor de Ficheiros (NAS)", "hosted_on", None, None, "Sala de Servidores", None),
    ("Switch Core", "Servidor Web / Intranet", "hosted_on", None, None, "Sala de Servidores", None),
    ("Switch Core", "Servidor de Backups", "hosted_on", None, None, "Sala de Servidores", None),
    ("Switch Core", "Câmara IP – Sala de Servidores", "connected_to", None, None, "Sala de Servidores", None),
    ("Switch Acesso – Piso 1", "Access Point Wi-Fi", "connected_to", None, None, "Piso 1", None),
    ("Switch Acesso – Piso 1", "Impressora Multifunções", "connected_to", None, None, "Piso 1", None),
    ("Switch Acesso – Piso 1", "Câmara IP – Entrada", "connected_to", None, None, "Entrada", None),
    ("Switch Acesso – Piso 1", "Workstation RH-01", "connected_to", None, None, "Piso 1", None),
    ("Switch Acesso – Piso 1", "Workstation RH-02", "connected_to", None, None, "Piso 1", None),
    ("Switch Acesso – Piso 1", "Workstation Financeiro-01", "connected_to", None, None, "Piso 1", None),
    ("Switch Acesso – Piso 1", "Workstation Financeiro-02", "connected_to", None, None, "Piso 1", None),
    ("Switch Acesso – Piso 1", "Workstation Financeiro-03", "connected_to", None, None, "Piso 1", None),
    ("Switch Acesso – Piso 1", "Workstation TI – Administrador", "connected_to", None, None, "Piso 1", None),
    ("Switch Acesso – Piso 1", "Workstation TI – Técnico", "connected_to", None, None, "Piso 1", None),
]

# Ligações sem fios ao AP (portáteis / postos mais móveis)
WIFI_CLIENTS = [
    "Portátil Diretor Geral", "Portátil Diretora Financeira",
    "Portátil Comercial-01", "Portátil Comercial-02",
    "Workstation Comercial-03", "Workstation Comercial-04", "Workstation Comercial-05",
    "Workstation Operações-01", "Workstation Operações-02",
    "Workstation Operações-03", "Workstation Operações-04",
    "Workstation Marketing-01", "Workstation Marketing-02",
]
for _name in WIFI_CLIENTS:
    RELATIONS.append(
        ("Access Point Wi-Fi", _name, "connected_via", "WPA2-Enterprise", None, "Wi-Fi Corporativo", None)
    )


# ====================================================================== #
# 3. Associação de colaboradores (utilizadores SOC) aos seus ativos
# ====================================================================== #
USER_ASSET_LINKS = [
    ("ana.silva", "Workstation Financeiro-01"),
    ("joao.costa", "Workstation Financeiro-03"),
    ("maria.fernandes", "Workstation TI – Administrador"),
    # admin (SOC) fica sem ativo — é a conta da plataforma, não um posto de trabalho.
    # pserrano mantém-se associado ao seu ativo atual (Portátil Comercial-01) — não tocado.
]


def main():
    try:
        assets = _get("/api/assets")
        users = _get("/api/users")
    except requests.exceptions.ConnectionError:
        print("ERRO: API offline. Corre primeiro: python api_main.py")
        sys.exit(1)

    by_name = {a["name"]: a for a in assets}
    by_username = {u["username"]: u for u in users}

    print(f"Ativos: {len(assets)} | Colaboradores: {len(users)}")

    # -- 1. Serviços/configuração -------------------------------------- #
    print("\n[1/3] Serviços e configurações...")
    n = 0
    for name, a in by_name.items():
        if name in SERVICES:
            services, config = SERVICES[name]
        elif a.get("asset_type") == "workstation":
            services, config = WEAK_WORKSTATION if name in WEAK_WORKSTATIONS else DEFAULT_WORKSTATION
        else:
            continue
        _put_asset(a["id"], a, services=services, config=config)
        n += 1
    print(f"  {n} ativos atualizados.")

    # -- 2. Relações de rede --------------------------------------------#
    print("\n[2/3] Relações de rede...")
    created, skipped = 0, 0
    for src, tgt, rtype, proto, port, zone, desc in RELATIONS:
        s, t = by_name.get(src), by_name.get(tgt)
        if not s or not t:
            print(f"  [skip] {src} -> {tgt} (ativo em falta)")
            skipped += 1
            continue
        r = requests.post(
            f"{API}/api/assets/{s['id']}/relations",
            json={
                "target_asset_id": t["id"], "relation_type": rtype,
                "protocol": proto, "port": port, "network_zone": zone,
                "description": desc,
            },
            timeout=10,
        )
        if r.status_code < 300:
            created += 1
        else:
            skipped += 1
    print(f"  {created} relações criadas, {skipped} ignoradas (já existiam ou ativo em falta).")

    # -- 3. Colaboradores <-> ativos -------------------------------------#
    print("\n[3/3] Associação de colaboradores a ativos...")
    for username, asset_name in USER_ASSET_LINKS:
        u, a = by_username.get(username), by_name.get(asset_name)
        if not u or not a:
            print(f"  [skip] {username} -> {asset_name} (não encontrado)")
            continue
        _put_user(u["id"], u, a["id"])
        _put_asset(a["id"], a, owner=u.get("full_name"))
        print(f"  {u.get('full_name')} -> {asset_name}")

    print("\nConcluído.")


if __name__ == "__main__":
    main()
