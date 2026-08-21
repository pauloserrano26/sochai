"""
demo_incidentes.py — Gera 12 incidentes simulados para demonstração do SOCHAI.

Cada cenário corresponde a uma das 12 ameaças do guia INCIBE adaptado ao contexto
de uma PME portuguesa, com IOCs realistas e mapeamento MITRE ATT&CK.

Uso:  python demo_incidentes.py
      python demo_incidentes.py --limpar   (apaga incidentes anteriores da demo)
A API (api_main.py) tem de estar em execução em http://localhost:8000
"""

import sys
import time
import argparse
import requests

from scenario_data import CENARIOS

API = "http://localhost:8000"


# ── Utilitários ────────────────────────────────────────────────────────────────

SEV_COLOR = {
    "CRITICA": "\033[91m",  # vermelho
    "ALTA":    "\033[93m",  # amarelo
    "MEDIA":   "\033[94m",  # azul
    "BAIXA":   "\033[92m",  # verde
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def check_api() -> bool:
    try:
        r = requests.get(f"{API}/health", timeout=5)
        return r.status_code == 200 and r.json().get("status") == "online"
    except Exception:
        return False


def criar_incidente(cenario: dict, idx: int) -> dict | None:
    payload = {
        "type":        cenario["type"],
        "description": cenario["description"],
        "severity":    cenario["severity"],
    }
    for campo in ("source_ip", "url", "hash", "port"):
        if campo in cenario:
            payload[campo] = cenario[campo]

    resp = requests.post(f"{API}/api/alerts", json=payload, timeout=30)
    if resp.status_code in (200, 201):
        return resp.json()
    print(f"  {SEV_COLOR['CRITICA']}[ERRO]{RESET} Cenário {idx}: {resp.text[:120]}")
    return None


def limpar_demo():
    """Remove incidentes cujo título começa com prefixo de demo."""
    incs = requests.get(f"{API}/api/incidents", params={"limit": 200}, timeout=10).json()
    if not isinstance(incs, list):
        print("Não foi possível obter incidentes.")
        return
    removidos = 0
    for inc in incs:
        # apagar apenas os criados por esta demo (description começa com ameaça em maiúsculas)
        desc = (inc.get("description") or "").upper()
        for kw in ["FUGA DE INFORMAÇÃO", "PHISHING", "FRAUDE DO CEO", "FRAUDE DE RH",
                   "SEXTORSÃO", "ATAQUE WEB", "RANSOMWARE", "FALSO SUPORTE",
                   "EMAIL COM MALWARE", "DDOS", "ADWARE", "SUPLANTAÇÃO"]:
            if kw in desc:
                requests.delete(f"{API}/api/incidents/{inc['incident_id']}", timeout=5)
                removidos += 1
                break
    print(f"  {removidos} incidente(s) de demo removidos.")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Gerador de incidentes demo MESI SOCHAI")
    parser.add_argument("--limpar", action="store_true",
                        help="Remove incidentes anteriores desta demo")
    args = parser.parse_args()

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}  MESI SOCHAI · Gerador de Incidentes Demo  (12 ameaças INCIBE){RESET}")
    print(f"{BOLD}{'='*65}{RESET}\n")

    print("  A verificar ligação à API...")
    if not check_api():
        print(f"  {SEV_COLOR['CRITICA']}ERRO:{RESET} API não está online.")
        print("  Inicie a API primeiro:  python api_main.py")
        sys.exit(1)
    print("  API online ✓\n")

    if args.limpar:
        print("  A limpar incidentes anteriores da demo...")
        limpar_demo()
        print()

    resultados = []
    print(f"  {'N°':<4} {'Ameaça':<40} {'Sev.':<9} {'Incidente':<22} {'ML':>6}  HITL")
    print(f"  {'-'*4} {'-'*40} {'-'*8} {'-'*22} {'-'*6}  {'-'*4}")

    for i, cenario in enumerate(CENARIOS, 1):
        nome = cenario["description"].split(" — ")[0].replace(" (BEC)", "").strip()[:38]
        sev  = cenario["severity"]
        cor  = SEV_COLOR.get(sev, "")

        result = criar_incidente(cenario, i)
        if result:
            inc_id   = result.get("incident_id", "—")
            ml_score = result.get("ml_score", 0)
            hitl_req = "✓ SIM" if result.get("hitl_required") else "  não"
            print(f"  {i:<4} {nome:<40} {cor}{sev:<8}{RESET} {inc_id:<22} {ml_score:>5.2f}  {hitl_req}")
            resultados.append({
                "n": i,
                "nome": nome,
                "sev": sev,
                "incident_id": inc_id,
                "ml_score": ml_score,
                "hitl": result.get("hitl_required", False),
                "playbook": cenario["playbook"],
                "hitl_note": cenario["hitl_note"],
                "soar": result.get("soar_actions_executed", 0),
            })
        else:
            print(f"  {i:<4} {nome:<40} {cor}{sev:<8}{RESET} {'ERRO':<22}")

        time.sleep(0.4)  # evitar sobrecarga da API

    # ── Resumo ──
    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}  RESUMO{RESET}")
    print(f"{'='*65}")
    criticos  = sum(1 for r in resultados if r["sev"] == "CRITICA")
    altos     = sum(1 for r in resultados if r["sev"] == "ALTA")
    medios    = sum(1 for r in resultados if r["sev"] == "MEDIA")
    hitl_cnt  = sum(1 for r in resultados if r["hitl"])
    soar_tot  = sum(r["soar"] for r in resultados)

    print(f"  Incidentes criados : {len(resultados)}/12")
    print(f"  Críticos           : {SEV_COLOR['CRITICA']}{criticos}{RESET}")
    print(f"  Altos              : {SEV_COLOR['ALTA']}{altos}{RESET}")
    print(f"  Médios             : {SEV_COLOR['MEDIA']}{medios}{RESET}")
    print(f"  Requerem HITL      : {hitl_cnt}")
    print(f"  Ações SOAR exec.   : {soar_tot}")

    print(f"\n{BOLD}  Incidentes que requerem revisão humana (HITL):{RESET}")
    for r in resultados:
        if r["hitl"]:
            print(f"  → [{r['incident_id']}] #{r['n']} {r['nome']}")
            print(f"      Playbook: {r['playbook']} | {r['hitl_note']}")

    print(f"\n{BOLD}  Próximos passos no dashboard:{RESET}")
    print("  1. Abre o tab 'XAI / HITL' — revisa os alertas pendentes")
    print("  2. Para cada alerta: lê o caminho de decisão XAI e decide")
    print("     VERDADEIRO_POSITIVO / FALSO_POSITIVO / ESCALAR")
    print("  3. Observa as ações SOAR executadas automaticamente")
    print("  4. Vê o tab '📊 Analytics' para o impacto consolidado")
    print("  5. Consulta os Playbooks (PB-001 a PB-014) para o processo de resposta")
    print(f"\n  Dashboard: {BOLD}http://localhost:8501{RESET}\n")


if __name__ == "__main__":
    main()
