"""
seed_colaboradores.py — Promove os responsáveis já registados no inventário a
colaboradores SOC, associando cada um ao seu posto de trabalho.

Os postos de trabalho do inventário já têm uma pessoa no campo `owner` (texto),
mas essa pessoa não existe como utilizador da plataforma — pelo que o ativo não
tem dono do ponto de vista do SOC. Sem esse elo, um incidente no ativo não sobe
o risco humano de ninguém nem gera missão de formação dirigida.

Este script fecha esse elo: para cada posto de trabalho sem colaborador
associado, cria o utilizador correspondente ao `owner` e liga-os.

Não inventa pessoas — a fonte dos nomes é o próprio inventário.
É idempotente: correr duas vezes não duplica nada.

Uso: python seed_colaboradores.py
A API (api_main.py) tem de estar em execução.
"""

import sys
import unicodedata

import requests

API = "http://localhost:8000"

# Tipos de ativo que representam um posto de trabalho pessoal — só estes têm
# um colaborador responsável. Servidores, switches e IoT são da equipa de TI.
POSTO_DE_TRABALHO = {"workstation"}

EMAIL_DOMAIN = "empresa.pt"

# Todos entram como "employee": é o role que as campanhas de simulação de
# phishing têm como alvo (ver PhishingCampaign em api_main.py) e o que faz
# sentido para formação, independentemente da posição na empresa.
DEFAULT_ROLE = "employee"


def _get(path):
    r = requests.get(f"{API}{path}", timeout=10)
    r.raise_for_status()
    return r.json()


def _post_user(payload):
    r = requests.post(f"{API}/api/users", json=payload, timeout=10)
    r.raise_for_status()
    return r.json()


def _put_user(user, asset_id):
    payload = {
        "username": user["username"], "email": user.get("email"),
        "full_name": user.get("full_name"), "role": user.get("role", DEFAULT_ROLE),
        "department": user.get("department"), "asset_id": asset_id,
    }
    r = requests.put(f"{API}/api/users/{user['id']}", json=payload, timeout=10)
    r.raise_for_status()
    return r.json()


def username_from_name(full_name: str) -> str:
    """'Inês Carvalho' -> 'ines.carvalho' (sem acentos, minúsculas)."""
    ascii_name = (
        unicodedata.normalize("NFKD", full_name)
        .encode("ascii", "ignore")
        .decode("ascii")
    )
    parts = [p for p in ascii_name.lower().split() if p]
    return ".".join(parts) if parts else ""


def main():
    try:
        assets = _get("/api/assets")
        users = _get("/api/users")
    except requests.exceptions.ConnectionError:
        print("ERRO: API offline. Corre primeiro: python api_main.py")
        sys.exit(1)

    by_username = {u["username"]: u for u in users}
    owned_asset_ids = {u["asset_id"] for u in users if u.get("asset_id")}

    candidates = [
        a for a in assets
        if a.get("asset_type") in POSTO_DE_TRABALHO
        and a.get("owner")
        and a["id"] not in owned_asset_ids
        and not a.get("linked_users")
    ]

    print(f"Ativos: {len(assets)} | Colaboradores atuais: {len(users)}")
    print(f"Postos de trabalho com responsável mas sem colaborador SOC: {len(candidates)}\n")

    created, linked, conflicts = 0, 0, []

    for asset in sorted(candidates, key=lambda a: a["name"]):
        full_name = asset["owner"].strip()
        username = username_from_name(full_name)
        if not username:
            conflicts.append((asset["name"], full_name, "nome inválido"))
            continue

        existing = by_username.get(username)
        if existing:
            # O nome já é um colaborador da plataforma. Só o associamos se ainda
            # não tiver posto atribuído — nunca lhe tiramos o ativo atual.
            if existing.get("asset_id"):
                conflicts.append((
                    asset["name"], full_name,
                    f"'{username}' já está associado a '{existing.get('asset_name')}'",
                ))
                continue
            _put_user(existing, asset["id"])
            owned_asset_ids.add(asset["id"])
            linked += 1
            print(f"  [ligado] {full_name:20} -> {asset['name']}")
            continue

        new_user = _post_user({
            "username": username,
            "email": f"{username}@{EMAIL_DOMAIN}",
            "full_name": full_name,
            "role": DEFAULT_ROLE,
            "department": asset.get("department"),
            "asset_id": asset["id"],
        })
        by_username[username] = new_user
        owned_asset_ids.add(asset["id"])
        created += 1
        print(f"  [criado] {username:22} {full_name:20} -> {asset['name']}")

    print(f"\n{created} colaborador(es) criado(s), {linked} associado(s) a um posto existente.")

    if conflicts:
        print("\nPor resolver manualmente (Gamificação -> Utilizadores):")
        for asset_name, full_name, reason in conflicts:
            print(f"  [!] {asset_name}: responsável '{full_name}' — {reason}")

    total = _get("/api/users")
    com_ativo = sum(1 for u in total if u.get("asset_id"))
    print(f"\nTotal: {len(total)} colaboradores, {com_ativo} com ativo associado.")
    print("Acessos ao portal: dashboard -> barra lateral -> 'Gerir acessos ao portal'.")


if __name__ == "__main__":
    main()
