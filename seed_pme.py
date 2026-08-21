"""
seed_pme.py — Adiciona ativos PME via API (sem apagar a base de dados).
Uso: python seed_pme.py
A API (api_main.py) tem de estar em execução.
"""

import sys
import requests

API = "http://localhost:8000"

PME_ASSETS = [
    # ── Infraestrutura de rede ─────────────────────────────────────────
    {"name": "Firewall Perimetral", "asset_type": "firewall",
     "ip_address": "10.0.0.1", "mac_address": "AA:BB:CC:00:00:01",
     "hostname": "fw-perimeter-01", "department": "TI", "criticality": "CRITICO",
     "os_system": "FortiOS 7.4", "location": "Sala de Servidores",
     "description": "Firewall de borda – protege toda a rede interna",
     "tags": ["firewall", "perimetro", "critico"]},
    {"name": "Router ISP Principal", "asset_type": "router",
     "ip_address": "10.0.0.254", "mac_address": "AA:BB:CC:00:00:02",
     "hostname": "rtr-isp-01", "department": "TI", "criticality": "CRITICO",
     "os_system": "Cisco IOS 15.7", "location": "Sala de Servidores",
     "description": "Router de ligação à internet (operadora principal)",
     "tags": ["router", "isp", "perimetro"]},
    {"name": "Switch Core L3", "asset_type": "switch",
     "ip_address": "192.168.1.1", "mac_address": "AA:BB:CC:00:01:01",
     "hostname": "sw-core-01", "department": "TI", "criticality": "ALTO",
     "os_system": "Cisco IOS 16.9", "location": "Sala de Servidores",
     "description": "Switch central que agrega todas as VLANs da empresa",
     "tags": ["switch", "core", "vlan"]},
    {"name": "Switch Acesso – Piso 1", "asset_type": "switch",
     "ip_address": "192.168.1.2", "mac_address": "AA:BB:CC:00:01:02",
     "hostname": "sw-access-01", "department": "TI", "criticality": "MEDIO",
     "location": "Armário de rede – Piso 1",
     "description": "Switch de acesso para postos de trabalho do piso 1",
     "tags": ["switch", "acesso"]},
    {"name": "Access Point Wi-Fi", "asset_type": "iot",
     "ip_address": "192.168.1.5", "mac_address": "AA:BB:CC:00:01:05",
     "hostname": "ap-wifi-01", "department": "TI", "criticality": "MEDIO",
     "os_system": "UniFi OS 3.2", "location": "Open Space",
     "description": "Ponto de acesso sem fios – rede corporativa e convidados",
     "tags": ["wifi", "wireless", "ap"]},
    # ── Servidores ─────────────────────────────────────────────────────
    {"name": "Servidor de Ficheiros (NAS)", "asset_type": "server",
     "ip_address": "192.168.1.10", "mac_address": "AA:BB:CC:00:02:10",
     "hostname": "nas-srv-01", "department": "TI", "criticality": "CRITICO",
     "os_system": "TrueNAS SCALE 23.10", "location": "Sala de Servidores",
     "description": "NAS central – armazenamento de ficheiros e backups",
     "tags": ["nas", "storage", "backup"]},
    {"name": "Servidor Web / Intranet", "asset_type": "server",
     "ip_address": "192.168.1.11", "mac_address": "AA:BB:CC:00:02:11",
     "hostname": "web-srv-01", "department": "TI", "criticality": "ALTO",
     "os_system": "Ubuntu Server 22.04 LTS", "location": "Sala de Servidores",
     "description": "Servidor web interno – intranet e portal de colaboradores",
     "tags": ["web", "intranet", "linux"]},
    {"name": "Servidor de Email", "asset_type": "server",
     "ip_address": "192.168.1.12", "mac_address": "AA:BB:CC:00:02:12",
     "hostname": "mail-srv-01", "department": "TI", "criticality": "ALTO",
     "os_system": "Windows Server 2022", "location": "Sala de Servidores",
     "description": "Microsoft Exchange – email corporativo",
     "tags": ["email", "exchange", "windows"]},
    {"name": "Servidor de Backups", "asset_type": "server",
     "ip_address": "192.168.1.15", "mac_address": "AA:BB:CC:00:02:15",
     "hostname": "backup-srv-01", "department": "TI", "criticality": "ALTO",
     "os_system": "Debian 12", "location": "Sala de Servidores",
     "description": "Servidor dedicado a backups diários e retenção de dados",
     "tags": ["backup", "linux"]},
    # ── Direção (2) ────────────────────────────────────────────────────
    {"name": "Portátil Diretor Geral", "asset_type": "workstation",
     "ip_address": "192.168.2.10", "mac_address": "AA:BB:CC:01:00:10",
     "hostname": "lt-dir-01", "owner": "Carlos Moura", "department": "Direção",
     "criticality": "ALTO", "os_system": "Windows 11 Pro",
     "description": "Portátil do Diretor Geral – acesso a dados sensíveis",
     "tags": ["laptop", "direcao", "movel"]},
    {"name": "Portátil Diretora Financeira", "asset_type": "workstation",
     "ip_address": "192.168.2.11", "mac_address": "AA:BB:CC:01:00:11",
     "hostname": "lt-dir-02", "owner": "Sofia Ramos", "department": "Direção",
     "criticality": "ALTO", "os_system": "Windows 11 Pro",
     "tags": ["laptop", "direcao", "movel"]},
    # ── TI (2) ─────────────────────────────────────────────────────────
    {"name": "Workstation TI – Administrador", "asset_type": "workstation",
     "ip_address": "192.168.2.20", "mac_address": "AA:BB:CC:01:01:20",
     "hostname": "ws-ti-01", "owner": "João Ferreira", "department": "TI",
     "criticality": "ALTO", "os_system": "Ubuntu 22.04 LTS",
     "description": "Workstation do administrador de sistemas",
     "tags": ["workstation", "ti", "admin"]},
    {"name": "Workstation TI – Técnico", "asset_type": "workstation",
     "ip_address": "192.168.2.21", "mac_address": "AA:BB:CC:01:01:21",
     "hostname": "ws-ti-02", "owner": "Beatriz Santos", "department": "TI",
     "criticality": "MEDIO", "os_system": "Windows 11 Pro",
     "tags": ["workstation", "ti"]},
    # ── Financeiro (3) ─────────────────────────────────────────────────
    {"name": "Workstation Financeiro-01", "asset_type": "workstation",
     "ip_address": "192.168.2.30", "mac_address": "AA:BB:CC:01:02:30",
     "hostname": "ws-fin-01", "owner": "Pedro Costa", "department": "Financeiro",
     "criticality": "ALTO", "os_system": "Windows 11 Pro",
     "description": "Posto do contabilista – acesso a software ERP",
     "tags": ["workstation", "financeiro", "erp"]},
    {"name": "Workstation Financeiro-02", "asset_type": "workstation",
     "ip_address": "192.168.2.31", "mac_address": "AA:BB:CC:01:02:31",
     "hostname": "ws-fin-02", "owner": "Marta Lopes", "department": "Financeiro",
     "criticality": "MEDIO", "os_system": "Windows 11 Pro",
     "tags": ["workstation", "financeiro"]},
    {"name": "Workstation Financeiro-03", "asset_type": "workstation",
     "ip_address": "192.168.2.32", "mac_address": "AA:BB:CC:01:02:32",
     "hostname": "ws-fin-03", "owner": "Rui Neves", "department": "Financeiro",
     "criticality": "MEDIO", "os_system": "Windows 10 Pro",
     "tags": ["workstation", "financeiro"]},
    # ── RH (2) ─────────────────────────────────────────────────────────
    {"name": "Workstation RH-01", "asset_type": "workstation",
     "ip_address": "192.168.2.40", "mac_address": "AA:BB:CC:01:03:40",
     "hostname": "ws-rh-01", "owner": "Ana Silva", "department": "RH",
     "criticality": "ALTO", "os_system": "Windows 11 Pro",
     "description": "Técnica de RH – dados pessoais RGPD",
     "tags": ["workstation", "rh", "rgpd"]},
    {"name": "Workstation RH-02", "asset_type": "workstation",
     "ip_address": "192.168.2.41", "mac_address": "AA:BB:CC:01:03:41",
     "hostname": "ws-rh-02", "owner": "Luísa Pinto", "department": "RH",
     "criticality": "MEDIO", "os_system": "Windows 11 Pro",
     "tags": ["workstation", "rh"]},
    # ── Comercial (5) ──────────────────────────────────────────────────
    {"name": "Portátil Comercial-01", "asset_type": "workstation",
     "ip_address": "192.168.2.50", "mac_address": "AA:BB:CC:01:04:50",
     "hostname": "lt-com-01", "owner": "Miguel Rodrigues", "department": "Comercial",
     "criticality": "MEDIO", "os_system": "Windows 11 Pro",
     "tags": ["laptop", "comercial", "movel"]},
    {"name": "Portátil Comercial-02", "asset_type": "workstation",
     "ip_address": "192.168.2.51", "mac_address": "AA:BB:CC:01:04:51",
     "hostname": "lt-com-02", "owner": "Carla Mendes", "department": "Comercial",
     "criticality": "MEDIO", "os_system": "Windows 11 Pro",
     "tags": ["laptop", "comercial", "movel"]},
    {"name": "Workstation Comercial-03", "asset_type": "workstation",
     "ip_address": "192.168.2.52", "mac_address": "AA:BB:CC:01:04:52",
     "hostname": "ws-com-03", "owner": "Tiago Oliveira", "department": "Comercial",
     "criticality": "BAIXO", "os_system": "Windows 11 Home",
     "tags": ["workstation", "comercial"]},
    {"name": "Workstation Comercial-04", "asset_type": "workstation",
     "ip_address": "192.168.2.53", "mac_address": "AA:BB:CC:01:04:53",
     "hostname": "ws-com-04", "owner": "Inês Carvalho", "department": "Comercial",
     "criticality": "BAIXO", "os_system": "Windows 11 Home",
     "tags": ["workstation", "comercial"]},
    {"name": "Workstation Comercial-05", "asset_type": "workstation",
     "ip_address": "192.168.2.54", "mac_address": "AA:BB:CC:01:04:54",
     "hostname": "ws-com-05", "owner": "André Fonseca", "department": "Comercial",
     "criticality": "BAIXO", "os_system": "Windows 10 Pro",
     "tags": ["workstation", "comercial"]},
    # ── Operações (4) ──────────────────────────────────────────────────
    {"name": "Workstation Operações-01", "asset_type": "workstation",
     "ip_address": "192.168.2.60", "mac_address": "AA:BB:CC:01:05:60",
     "hostname": "ws-ops-01", "owner": "Filipa Gomes", "department": "Operações",
     "criticality": "MEDIO", "os_system": "Windows 11 Pro",
     "tags": ["workstation", "operacoes"]},
    {"name": "Workstation Operações-02", "asset_type": "workstation",
     "ip_address": "192.168.2.61", "mac_address": "AA:BB:CC:01:05:61",
     "hostname": "ws-ops-02", "owner": "Nuno Alves", "department": "Operações",
     "criticality": "MEDIO", "os_system": "Windows 11 Pro",
     "tags": ["workstation", "operacoes"]},
    {"name": "Workstation Operações-03", "asset_type": "workstation",
     "ip_address": "192.168.2.62", "mac_address": "AA:BB:CC:01:05:62",
     "hostname": "ws-ops-03", "owner": "Sandra Cruz", "department": "Operações",
     "criticality": "BAIXO", "os_system": "Windows 10 Pro",
     "tags": ["workstation", "operacoes"]},
    {"name": "Workstation Operações-04", "asset_type": "workstation",
     "ip_address": "192.168.2.63", "mac_address": "AA:BB:CC:01:05:63",
     "hostname": "ws-ops-04", "owner": "Bruno Marques", "department": "Operações",
     "criticality": "BAIXO", "os_system": "Windows 10 Pro",
     "tags": ["workstation", "operacoes"]},
    # ── Marketing (2) ──────────────────────────────────────────────────
    {"name": "Workstation Marketing-01", "asset_type": "workstation",
     "ip_address": "192.168.2.70", "mac_address": "AA:BB:CC:01:06:70",
     "hostname": "ws-mkt-01", "owner": "Vera Sousa", "department": "Marketing",
     "criticality": "BAIXO", "os_system": "macOS Ventura 13",
     "tags": ["workstation", "marketing", "mac"]},
    {"name": "Workstation Marketing-02", "asset_type": "workstation",
     "ip_address": "192.168.2.71", "mac_address": "AA:BB:CC:01:06:71",
     "hostname": "ws-mkt-02", "owner": "Diogo Teixeira", "department": "Marketing",
     "criticality": "BAIXO", "os_system": "macOS Sonoma 14",
     "tags": ["workstation", "marketing", "mac"]},
    # ── IoT / Periféricos ──────────────────────────────────────────────
    {"name": "Impressora Multifunções", "asset_type": "iot",
     "ip_address": "192.168.3.10", "mac_address": "AA:BB:CC:02:00:10",
     "hostname": "printer-01", "department": "TI", "criticality": "BAIXO",
     "location": "Open Space",
     "description": "Impressora de rede partilhada por todos os colaboradores",
     "tags": ["iot", "impressora", "printer"]},
    {"name": "Câmara IP – Entrada", "asset_type": "iot",
     "ip_address": "192.168.3.20", "mac_address": "AA:BB:CC:02:00:20",
     "hostname": "cam-entrada-01", "department": "Operações", "criticality": "MEDIO",
     "location": "Entrada principal",
     "description": "Câmara de videovigilância – entrada do edifício",
     "tags": ["iot", "camera", "cctv", "seguranca"]},
    {"name": "Câmara IP – Sala de Servidores", "asset_type": "iot",
     "ip_address": "192.168.3.21", "mac_address": "AA:BB:CC:02:00:21",
     "hostname": "cam-srv-01", "department": "TI", "criticality": "ALTO",
     "location": "Sala de Servidores",
     "description": "Câmara de videovigilância – sala de servidores",
     "tags": ["iot", "camera", "cctv", "seguranca"]},
]


def main():
    print("A verificar ligação à API...")
    try:
        r = requests.get(f"{API}/health", timeout=5)
        if r.status_code != 200 or r.json().get("status") != "online":
            print("ERRO: API não está online. Inicie: python api_main.py")
            sys.exit(1)
    except Exception as e:
        print(f"ERRO: Não foi possível ligar à API — {e}")
        sys.exit(1)

    print("A carregar ativos existentes...")
    existing = requests.get(f"{API}/api/assets", timeout=10).json()
    existing_names = {a["name"] for a in existing} if isinstance(existing, list) else set()
    print(f"  {len(existing_names)} ativo(s) já existente(s).")

    created, skipped = 0, 0
    for asset in PME_ASSETS:
        if asset["name"] in existing_names:
            print(f"  [SKIP] {asset['name']}")
            skipped += 1
            continue
        resp = requests.post(f"{API}/api/assets", json=asset, timeout=10)
        if resp.status_code in (200, 201):
            print(f"  [OK]   {asset['name']}")
            created += 1
        else:
            print(f"  [ERR]  {asset['name']} — {resp.text[:80]}")

    print(f"\nConcluído: {created} criado(s), {skipped} ignorado(s).")


if __name__ == "__main__":
    main()
