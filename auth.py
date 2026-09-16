"""
Autenticação simples baseada em ficheiro para o SOCHAI Dashboard.

Dois níveis de acesso:
  - "staff"       -> acesso total à plataforma SOC (todas as tabs)
  - "colaborador" -> apenas Gamificação, Playbooks e a vista de Incidentes
                     (em curso / por resolver / resolvidos)

Uma conta "colaborador" pode ficar associada a um ``user_id`` do perfil de
gamificação (tabela ``Utilizadores`` da API, endpoint ``/api/users``). Quando
associada, o portal usa sempre essa identidade — o colaborador nunca escolhe
"jogar como" outro utilizador, pelo que não tem acesso aos dados/ações de
mais ninguém.

As credenciais ficam guardadas em ``users_auth.json`` (criado no primeiro
arranque a partir de ``_DEFAULT_USERS``). As palavras-passe nunca são
guardadas em claro — apenas o SHA-256.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import string
from typing import List, Optional

import streamlit as st

_STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users_auth.json")

# Utilizadores criados no primeiro arranque. Depois disso, a fonte de verdade
# passa a ser o ficheiro users_auth.json.
_DEFAULT_USERS = {
    "admin":       {"password": "sochai123", "role": "staff",       "name": "Administrador SOC"},
    "analista":    {"password": "sochai123", "role": "staff",       "name": "Analista SOC"},
    "colaborador": {"password": "colab123",  "role": "colaborador", "name": "Colaborador"},
}

ROLES = ("staff", "colaborador")


def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


def generate_password(length: int = 10) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _save_users(users: dict) -> None:
    with open(_STORE, "w", encoding="utf-8") as fh:
        json.dump(users, fh, indent=2, ensure_ascii=False)


def _load_users() -> dict:
    if os.path.exists(_STORE):
        try:
            with open(_STORE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            pass
    users = {
        u: {"password_hash": _hash(d["password"]), "role": d["role"], "name": d["name"]}
        for u, d in _DEFAULT_USERS.items()
    }
    _save_users(users)
    return users


# ------------------------------------------------------------------ #
# API pública
# ------------------------------------------------------------------ #

def list_users() -> dict:
    """{username: {"role", "name", "user_id"}} — sem hashes."""
    return {
        u: {
            "role": d.get("role", "colaborador"),
            "name": d.get("name", u),
            "user_id": d.get("user_id"),
        }
        for u, d in _load_users().items()
    }


def linked_user_ids() -> set:
    """user_id (perfil de gamificação) já associados a alguma conta do portal."""
    return {
        d["user_id"] for d in _load_users().values() if d.get("user_id") is not None
    }


def add_user(username: str, password: str, role: str, name: str = "", user_id: Optional[int] = None) -> None:
    username = username.strip()
    if not username or not password:
        raise ValueError("Utilizador e palavra-passe são obrigatórios.")
    if role not in ROLES:
        raise ValueError(f"Role inválido: {role}")
    users = _load_users()
    users[username] = {
        "password_hash": _hash(password),
        "role": role,
        "name": name.strip() or username,
        "user_id": user_id,
    }
    _save_users(users)


def delete_user(username: str) -> None:
    users = _load_users()
    users.pop(username, None)
    _save_users(users)


def provision_bulk(soc_users: List[dict], role: str = "colaborador") -> List[dict]:
    """
    Cria uma conta de acesso para cada utilizador SOC (``/api/users``) que
    ainda não tenha uma associada, ligada ao respetivo ``user_id`` — assim
    cada colaborador só consegue jogar/reportar como ele próprio.

    Devolve a lista [{"username","name","password"}] das contas CRIADAS
    agora (a palavra-passe só existe em claro nesta resposta — mostrar
    uma única vez ao admin e depois é só o hash que fica guardado).
    """
    users = _load_users()
    already_linked = {d["user_id"] for d in users.values() if d.get("user_id") is not None}
    created = []
    for su in soc_users:
        uid = su.get("id")
        if uid is None or uid in already_linked:
            continue
        username = (su.get("username") or f"user{uid}").strip()
        base_username = username
        n = 2
        while username in users:
            username = f"{base_username}{n}"
            n += 1
        password = generate_password()
        users[username] = {
            "password_hash": _hash(password),
            "role": role,
            "name": su.get("full_name") or username,
            "user_id": uid,
        }
        created.append({"username": username, "name": users[username]["name"], "password": password})
    if created:
        _save_users(users)
    return created


def _check(username: str, password: str) -> Optional[dict]:
    u = _load_users().get(username)
    if u and u.get("password_hash") == _hash(password):
        return {
            "username": username,
            "role": u.get("role", "colaborador"),
            "name": u.get("name", username),
            "user_id": u.get("user_id"),
        }
    return None


def current_user() -> Optional[dict]:
    return st.session_state.get("auth_user")


def logout() -> None:
    st.session_state.pop("auth_user", None)


def require_login() -> dict:
    """Garante uma sessão autenticada. Bloqueia a app (st.stop) enquanto não houver."""
    user = st.session_state.get("auth_user")
    if user:
        return user

    _, mid, _ = st.columns([1, 1.4, 1])
    with mid:
        st.markdown("# 🛡️ SOCHAI Platform")
        st.caption("Security Operations Center — iniciar sessão")
        with st.form("login_form"):
            username = st.text_input("Utilizador")
            password = st.text_input("Palavra-passe", type="password")
            ok = st.form_submit_button("Entrar", use_container_width=True)
        if ok:
            u = _check(username.strip(), password)
            if u:
                st.session_state["auth_user"] = u
                st.rerun()
            else:
                st.error("Credenciais inválidas.")
    st.stop()
