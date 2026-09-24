"""
SOCHAI Dashboard — Streamlit
7 tabs: Ativos | SOCHAI Operations | Playbooks | XAI/HITL | Gamificação | Analytics | Cenários
"""

import math
from datetime import datetime
from typing import Dict, List, Optional

import altair as alt
import pandas as pd
import requests
import streamlit as st

import auth
import portal_colaborador
import ui_state

# 127.0.0.1 e não "localhost": nesta máquina "localhost" resolve primeiro para
# ::1, e a API escuta em 0.0.0.0 (só IPv4), pelo que cada pedido esperava ~2 s
# pelo timeout do IPv6 antes de tentar o IPv4. Medido: 2049 ms → 4 ms por pedido.
API_BASE = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="SOCHAI Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ------------------------------------------------------------------ #
# CSS
# ------------------------------------------------------------------ #
st.markdown("""
<style>
.metric-card {
    background: linear-gradient(135deg, #0d1526 0%, #112240 100%);
    border: 1px solid #1e3a5f;
    border-radius: 10px;
    padding: 1rem 1.2rem;
    text-align: center;
    margin-bottom: 0.5rem;
}
.metric-card .label { color: #8899aa; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 1px; }
.metric-card .value { color: #00d4ff; font-size: 2rem; font-weight: 700; }
.metric-card .value.red { color: #ff4757; }
.metric-card .value.green { color: #2ed573; }
.metric-card .value.yellow { color: #ffd700; }
</style>
""", unsafe_allow_html=True)


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

@st.cache_data(ttl=6, show_spinner=False)
def _cached_get(path: str, params: Optional[dict], timeout: int):
    try:
        resp = requests.get(f"{API_BASE}{path}", params=params, timeout=timeout)
        if resp.status_code < 300:
            return resp.json()
        return {"error": resp.text}
    except requests.exceptions.ConnectionError:
        return {"error": "API offline — inicie: python api_main.py"}
    except Exception as e:
        return {"error": str(e)}


def api(method: str, path: str, **kwargs):
    timeout = kwargs.pop("timeout", 10)

    # GET requests are read-only, so Streamlit's per-script rerun (every
    # widget interaction reruns the whole file) can reuse a short-lived
    # cached response instead of re-hitting the API every time.
    if method == "get":
        return _cached_get(path, kwargs.get("params"), timeout)

    try:
        resp = getattr(requests, method)(f"{API_BASE}{path}", timeout=timeout, **kwargs)
        if resp.status_code < 300:
            # Mutation succeeded — drop cached GETs so the next read isn't stale.
            _cached_get.clear()
            return resp.json()
        return {"error": resp.text}
    except requests.exceptions.ConnectionError:
        return {"error": "API offline — inicie: python api_main.py"}
    except Exception as e:
        return {"error": str(e)}


def sev_icon(s: str) -> str:
    return {"CRITICA": "🔴", "ALTA": "🟠", "MEDIA": "🟡", "BAIXA": "🟢"}.get(
        (s or "").upper(), "⚪"
    )


def status_label(s: str) -> str:
    return {
        "open": "🔵 Aberto",
        "investigating": "🟡 Em Investigação",
        "resolved": "🟢 Resolvido",
        "closed": "⚫ Fechado",
    }.get(s, s)


def metric_card(label: str, value, color: str = "") -> str:
    color_class = f" {color}" if color else ""
    return (
        f'<div class="metric-card">'
        f'<div class="label">{label}</div>'
        f'<div class="value{color_class}">{value}</div>'
        f'</div>'
    )


def fmt_minutes(value) -> str:
    """Minutos → '—' | '42 min' | '3h 05m' | '2d 4h', para leitura rápida nos KPIs."""
    if value is None:
        return "—"
    mins = float(value)
    if mins < 90:
        return f"{mins:.0f} min"
    hours = mins / 60
    if hours < 48:
        return f"{int(hours)}h {int(mins % 60):02d}m"
    return f"{int(hours // 24)}d {int(hours % 24)}h"


def fmt_pct(value) -> str:
    return "—" if value is None else f"{value:.1f}%"


def api_online() -> bool:
    r = api("get", "/health")
    return isinstance(r, dict) and r.get("status") == "online"


# ------------------------------------------------------------------ #
# Autenticação e controlo de acesso
# ------------------------------------------------------------------ #

user = auth.require_login()

# Repõe a vista gravada no fim da última utilização — tem de correr antes de
# qualquer widget ser criado, senão o Streamlit já fixou os valores iniciais.
ui_state.restore(user["username"])

with st.sidebar:
    st.markdown("# 🛡️ MESI SOCHAI")
    st.caption(f"Sessão: **{user['name']}** · `{user['role']}`")
    if st.button("🚪 Terminar sessão", use_container_width=True):
        auth.logout()
        st.rerun()

    if user["role"] == "staff":
        with st.expander("👥 Gerir acessos ao portal"):
            existing = auth.list_users()
            soc_users = api("get", "/api/users")
            soc_users = soc_users if isinstance(soc_users, list) else []
            soc_by_id = {u["id"]: u for u in soc_users}

            st.caption("Contas atuais:")
            for uname, meta in existing.items():
                linked = soc_by_id.get(meta.get("user_id"))
                tag = f" → perfil: **{linked['full_name']}**" if linked else ""
                cols = st.columns([3, 1])
                cols[0].write(f"`{uname}` — {meta['name']} ({meta['role']}){tag}")
                if uname != user["username"] and cols[1].button("🗑️", key=f"del_{uname}"):
                    auth.delete_user(uname)
                    st.rerun()

            st.divider()
            st.caption(
                "Cada conta ligada a um perfil só consegue jogar/reportar como "
                "esse utilizador — nunca em nome de outro."
            )
            pending = [u for u in soc_users if u["id"] not in auth.linked_user_ids()]
            if pending:
                st.write(f"**{len(pending)}** utilizador(es) sem acesso ao portal.")
                if st.button("🚀 Criar acessos para todos", use_container_width=True):
                    created = auth.provision_bulk(soc_users, role="colaborador")
                    st.session_state["_new_portal_accounts"] = created
                    st.rerun()
            else:
                st.success("Todos os utilizadores já têm acesso ao portal.")

            new_accs = st.session_state.pop("_new_portal_accounts", None)
            if new_accs:
                st.warning("⚠️ Anota estas credenciais agora — não voltam a ser mostradas:")
                st.dataframe(
                    [{"Utilizador": a["username"], "Nome": a["name"], "Palavra-passe": a["password"]} for a in new_accs],
                    use_container_width=True, hide_index=True,
                )

            st.divider()
            with st.form("new_access_form"):
                st.caption("Criar acesso manual")
                link_options = ["— nenhum (conta avulsa) —"] + [
                    f"{u['full_name']} ({u['username']})" for u in soc_users if u["id"] not in auth.linked_user_ids()
                ]
                na_link = st.selectbox("Associar a utilizador", link_options)
                na_user = st.text_input("Utilizador (login) *")
                na_name = st.text_input("Nome")
                na_role = st.selectbox("Nível de acesso", ["colaborador", "staff"])
                na_pw = st.text_input("Palavra-passe *", type="password")
                if st.form_submit_button("Criar acesso", use_container_width=True):
                    try:
                        na_uid = None
                        if na_link != link_options[0]:
                            na_uid = [u for u in soc_users if u["id"] not in auth.linked_user_ids()][
                                link_options.index(na_link) - 1
                            ]["id"]
                        auth.add_user(na_user, na_pw, na_role, na_name, user_id=na_uid)
                        st.success(f"Acesso '{na_user}' criado.")
                    except ValueError as e:
                        st.error(str(e))
    st.divider()

# Colaboradores só têm acesso ao portal restrito.
if user["role"] != "staff":
    portal_colaborador.render(user)
    st.stop()

with st.sidebar:
    st.markdown("**Security Operations Center**")
    st.divider()

    online = api_online()
    if online:
        st.success("🟢 API Online")
    else:
        st.error("🔴 API Offline")
        st.code("python api_main.py", language="bash")

    st.divider()
    if online:
        ov = api("get", "/api/analytics/overview")
        if isinstance(ov, dict) and "incidents" in ov:
            inc = ov["incidents"]
            st.metric("Incidentes Abertos", inc.get("open", 0))
            st.metric("Em Investigação", inc.get("investigating", 0))
            st.metric("HITL Pendentes", ov.get("hitl", {}).get("pending_count", 0))

    st.divider()
    if st.button("🔄 Atualizar Dados", use_container_width=True):
        st.rerun()

    # ---------------------------------------------------------------- #
    # Estado da sessão entre arranques
    # ---------------------------------------------------------------- #
    st.divider()
    st.caption("**Estado da sessão**")

    _snap = ui_state.saved_at(user["username"])
    if not _snap:
        st.caption("Sem estado gravado para esta conta.")
    elif ui_state.was_restored():
        st.caption(f"↩️ Vista reposta do estado de {_snap[:16].replace('T', ' ')}")
    else:
        st.caption(f"💾 Último estado gravado: {_snap[:16].replace('T', ' ')}")

    if st.button("💾 Guardar estado", use_container_width=True,
                 help="Grava a tab ativa, os filtros e os últimos resultados de cenários "
                      "e simulações, para os reencontrar no próximo arranque."):
        ui_state.save(user["username"])
        st.rerun()

    if st.button("🚪 Guardar e encerrar", use_container_width=True,
                 help="Grava o estado e desliga o servidor da dashboard."):
        ui_state.save(user["username"])
        st.session_state["_shutting_down"] = True
        st.rerun()

    if _snap and st.button("🧹 Esquecer estado gravado", use_container_width=True,
                           help="Apaga o snapshot: o próximo arranque começa limpo."):
        ui_state.clear(user["username"])
        st.rerun()

if st.session_state.get("_shutting_down"):
    st.success(
        f"💾 Estado gravado em `{ui_state.path_for(user['username'])}`.\n\n"
        "A dashboard está a encerrar — pode fechar este separador. "
        "No próximo `arrancar.bat` a vista é reposta a partir deste ponto."
    )
    st.caption("A API (porta 8000) continua a correr; feche a janela \"MESI API\" para a parar.")
    ui_state.request_shutdown()
    st.stop()


# ------------------------------------------------------------------ #
# Tabs
# ------------------------------------------------------------------ #

TAB_LABELS = [
    "🖥️ Ativos",
    "🚨 SOCHAI Operations",
    "📋 Playbooks",
    "🔬 XAI / HITL",
    "🎮 Gamificação",
    "📊 Analytics",
    "🎬 Cenários",
    "📈 Resultados",
]

# on_change="rerun" é o que faz o Streamlit expor a tab ativa em
# st.session_state["main_tab"] — sem isso as tabs são puramente do lado do
# cliente e não há forma de saber onde o utilizador estava para gravar.
# keep_valid protege contra um snapshot antigo apontar para uma tab renomeada.
ui_state.keep_valid(ui_state.TAB_WIDGET_KEY, TAB_LABELS)
tabs = st.tabs(TAB_LABELS, key=ui_state.TAB_WIDGET_KEY, on_change="rerun")
ui_state.track_active_tab(TAB_LABELS[0])


# ================================================================== #
# TAB 2 — SOCHAI Operations
# ================================================================== #
with tabs[1]:
    st.header("🚨 SOCHAI Operations — Pipeline L1→L6")

    col_form, col_list = st.columns([1, 1.4], gap="large")

    with col_form:
        st.subheader("Submeter Alerta")

        asset_options = api("get", "/api/assets", params={})
        asset_list = asset_options if isinstance(asset_options, list) else []
        asset_choices = ["🔎 Auto (detetar por IP)"] + [
            f"{a['name']} — {a.get('ip_address') or 's/ IP'} [{a.get('criticality') or '—'}]"
            for a in asset_list
        ]

        with st.form("alert_form"):
            alert_type = st.selectbox(
                "Tipo de Ameaça",
                ["malware", "phishing", "ransomware", "intrusion", "ddos",
                 "data_exfiltration", "brute_force", "account_compromise", "scan", "other"],
            )
            severity = st.selectbox("Severidade", ["CRITICA", "ALTA", "MEDIA", "BAIXA"])
            description = st.text_area("Descrição do Incidente", height=100)
            source_ip = st.text_input("IP de Origem (opcional)")
            url_ioc = st.text_input("URL / Domínio (opcional)")
            hash_ioc = st.text_input("Hash de Ficheiro (opcional)")
            port_ioc = st.number_input("Porta (opcional)", min_value=0, max_value=65535, value=0)
            asset_choice = st.selectbox("Ativo Afetado", asset_choices)

            submitted = st.form_submit_button("🚀 Submeter Alerta", use_container_width=True)

        if submitted:
            if not description.strip():
                st.error("A descrição é obrigatória.")
            else:
                payload = {
                    "type": alert_type,
                    "description": description,
                    "severity": severity,
                }
                if source_ip:
                    payload["source_ip"] = source_ip
                if url_ioc:
                    payload["url"] = url_ioc
                if hash_ioc:
                    payload["hash"] = hash_ioc
                if port_ioc:
                    payload["port"] = port_ioc
                if asset_choice != asset_choices[0]:
                    sel_idx = asset_choices.index(asset_choice) - 1
                    payload["asset_id"] = asset_list[sel_idx]["id"]

                with st.spinner("A processar alerta no pipeline SOCHAI..."):
                    result = api("post", "/api/alerts", json=payload)

                if "error" in result:
                    st.error(result["error"])
                else:
                    st.success(f"✅ Incidente criado: **{result['incident_id']}**")

                    ml_score = result.get("ml_score", 0)
                    score_pct = int(ml_score * 100)
                    st.progress(score_pct, text=f"Score de Anomalia ML: {score_pct}%")

                    col_r1, col_r2 = st.columns(2)
                    col_r1.write(f"**Decisão ML:** {result.get('xai_summary', '—')}")
                    col_r2.write(f"**Playbook:** {result.get('playbook_id', '—')}")
                    st.write(
                        f"**Ativo Afetado:** {result.get('asset_name') or '— (nenhum ativo correspondente)'}"
                    )
                    st.write(f"**Ação Recomendada:** {result.get('recommended_action', '—')}")
                    st.write(f"**Ações SOAR Executadas:** {result.get('soar_actions_executed', 0)}")

                    affected = result.get("affected_users") or []
                    if affected:
                        st.warning(
                            "**🎯 Colaboradores refletidos por este incidente** "
                            "(risk score atualizado + missão de formação gerada):"
                        )
                        for au in affected:
                            st.write(
                                f"- {au.get('full_name') or au.get('username')} "
                                f"— novo Risk Score: **{au.get('new_risk_score')}**"
                            )

                    with st.expander("🔍 Ver Análise XAI Detalhada"):
                        xai = result.get("xai_report", {})
                        factors = xai.get("top_contributing_factors", [])
                        if factors:
                            st.write("**Fatores Contribuintes:**")
                            for f in factors:
                                imp = {"alto": "🔴", "médio": "🟡", "baixo": "🟢"}.get(
                                    f.get("impact", ""), "⚪"
                                )
                                st.write(f"  {imp} {f['description']}")
                        path = xai.get("decision_path", [])
                        if path:
                            st.write("**Caminho de Decisão:**")
                            for step in path:
                                st.write(f"  → {step}")

                    if result.get("hitl_required"):
                        st.warning("⚠️ Esta alerta requer revisão humana — ver tab **XAI / HITL**")

    with col_list:
        st.subheader("Incidentes Recentes")
        status_filter = st.selectbox(
            "Filtrar por estado",
            ["Todos", "open", "investigating", "resolved", "closed"],
            key="inc_filter",
        )
        incidents = api(
            "get", "/api/incidents",
            params={"status": status_filter if status_filter != "Todos" else None, "limit": 30},
        )

        if isinstance(incidents, list) and incidents:
            _inc_assets = api("get", "/api/assets", params={})
            inc_asset_list = _inc_assets if isinstance(_inc_assets, list) else []
            reassoc_choices = ["— nenhum —"] + [
                f"{a['name']} — {a.get('ip_address') or 's/ IP'}" for a in inc_asset_list
            ]
            for inc in incidents:
                sev = inc.get("severity", "MEDIA")
                with st.expander(
                    f"{sev_icon(sev)} [{inc['incident_id']}] {inc.get('title', '—')} "
                    f"— {status_label(inc.get('status', ''))}"
                ):
                    c1, c2, c3 = st.columns(3)
                    c1.metric("ML Score", f"{(inc.get('ml_score') or 0):.2f}")
                    c2.metric(
                        "HITL",
                        "✅ Revisto" if inc.get("hitl_reviewed")
                        else "⏳ Pendente" if inc.get("hitl_required")
                        else "—",
                    )
                    c3.metric("Playbook", inc.get("playbook_id") or "—")
                    st.caption(f"Criado: {(inc.get('created_at') or '')[:16]}")

                    if inc.get("asset_name"):
                        st.write(
                            f"**🖥️ Ativo Afetado:** {inc['asset_name']} "
                            f"({inc.get('asset_criticality') or '—'})"
                        )
                    else:
                        st.write("**🖥️ Ativo Afetado:** — nenhum")

                    cur_idx = 0
                    for i, a in enumerate(inc_asset_list):
                        if a["id"] == inc.get("asset_id"):
                            cur_idx = i + 1
                            break
                    new_assoc = st.selectbox(
                        "Associar a ativo",
                        reassoc_choices,
                        index=cur_idx,
                        key=f"assoc_{inc['incident_id']}",
                    )
                    if st.button("Guardar ativo", key=f"saveassoc_{inc['incident_id']}"):
                        params = {}
                        if new_assoc != reassoc_choices[0]:
                            params["asset_id"] = inc_asset_list[
                                reassoc_choices.index(new_assoc) - 1
                            ]["id"]
                        api(
                            "patch",
                            f"/api/incidents/{inc['incident_id']}/asset",
                            params=params,
                        )
                        st.rerun()

                    new_status = st.selectbox(
                        "Alterar Estado",
                        ["open", "investigating", "resolved", "closed"],
                        index=["open", "investigating", "resolved", "closed"].index(
                            inc.get("status", "open")
                        ),
                        key=f"status_{inc['incident_id']}",
                    )
                    if st.button("Atualizar", key=f"upd_{inc['incident_id']}"):
                        api(
                            "patch",
                            f"/api/incidents/{inc['incident_id']}/status",
                            params={"status": new_status},
                        )
                        st.rerun()
        elif isinstance(incidents, dict) and "error" in incidents:
            st.error(incidents["error"])
        else:
            st.info("Sem incidentes registados. Submeta a primeira alerta.")


# ================================================================== #
# TAB 1 — Ativos
# ================================================================== #
with tabs[0]:
    st.header("🖥️ Gestão de Ativos da Empresa")

    act_tabs = st.tabs(["📋 Lista de Ativos", "🕸️ Topologia da Rede", "➕ Adicionar Ativo"])

    with act_tabs[0]:
        c1, c2, c3 = st.columns(3)
        dept_filter = c1.text_input("Departamento", key="asset_dept")
        crit_filter = c2.selectbox(
            "Criticidade", ["Todos", "CRITICO", "ALTO", "MEDIO", "BAIXO"], key="asset_crit"
        )
        type_filter = c3.selectbox(
            "Tipo",
            ["Todos", "server", "workstation", "router", "switch", "firewall", "iot", "other"],
            key="asset_type_f",
        )

        params = {}
        if dept_filter:
            params["department"] = dept_filter
        if crit_filter != "Todos":
            params["criticality"] = crit_filter
        if type_filter != "Todos":
            params["asset_type"] = type_filter

        assets = api("get", "/api/assets", params=params)

        crit_icons = {"CRITICO": "🔴", "ALTO": "🟠", "MEDIO": "🟡", "BAIXO": "🟢"}

        if isinstance(assets, list) and assets:
            # Summary counts
            cc1, cc2, cc3, cc4 = st.columns(4)
            cc1.metric("Total Ativos", len(assets))
            cc2.metric("Críticos", sum(1 for a in assets if (a.get("criticality") or "").upper() == "CRITICO"))
            cc3.metric("Altos", sum(1 for a in assets if (a.get("criticality") or "").upper() == "ALTO"))
            cc4.metric("Médios/Baixos", sum(1 for a in assets if (a.get("criticality") or "").upper() in ("MEDIO", "BAIXO")))
            st.divider()

            for a in assets:
                crit = (a.get("criticality") or "MEDIO").upper()
                icon = crit_icons.get(crit, "⚪")
                with st.expander(
                    f"{icon} **{a['name']}** [{a.get('asset_type', '—')}] "
                    f"— IP: {a.get('ip_address', 'N/A')} | Dept: {a.get('department', '—')}"
                ):
                    ca, cb, cc = st.columns(3)
                    ca.write(f"**Hostname:** {a.get('hostname') or '—'}")
                    ca.write(f"**MAC:** {a.get('mac_address') or '—'}")
                    cb.write(f"**SO:** {a.get('os_system') or '—'}")
                    cb.write(f"**Localização:** {a.get('location') or '—'}")
                    cc.write(f"**Responsável:** {a.get('owner') or '—'}")
                    cc.write(f"**Criticidade:** {icon} {crit}")
                    linked = a.get("linked_users") or []
                    cc.write(
                        "**Colaborador associado (SOC):** "
                        + (", ".join(u.get("full_name") or u["username"] for u in linked) or "—")
                    )
                    if a.get("description"):
                        st.caption(a["description"])
                    if a.get("tags"):
                        st.write(" ".join(f"`{t}`" for t in a["tags"]))

                    st.divider()
                    services = a.get("services") or []
                    cfg = a.get("config") or {}
                    if services or cfg:
                        st.write("**⚙️ Serviços e Configuração**")
                        if services:
                            for svc in services:
                                port = svc.get("port")
                                port_str = f":{port}" if port else ""
                                exposed = " 🌐 exposto à internet" if svc.get("exposed") else ""
                                ver = f" — {svc['version']}" if svc.get("version") else ""
                                st.markdown(
                                    f"- `{svc.get('name')}{port_str}/{svc.get('protocol')}`{ver}{exposed}"
                                )
                        if cfg:
                            cf1, cf2, cf3 = st.columns(3)
                            cf1.write(f"**Patch em dia:** {'✅' if cfg.get('os_patched') else '❌'}")
                            cf1.write(f"**MFA:** {'✅' if cfg.get('mfa_enabled') else '❌'}")
                            cf2.write(f"**AV/EDR:** {cfg.get('av_edr_agent') or '—'}")
                            cf2.write(f"**Exposto à internet:** {'⚠️ Sim' if cfg.get('internet_facing') else 'Não'}")
                            cf3.write(f"**Backups:** {'✅' if cfg.get('backup_enabled') else '❌'}")
                            cf3.write(f"**Encriptação em repouso:** {'✅' if cfg.get('encryption_at_rest') else '❌'}")
                            if cfg.get("known_weaknesses"):
                                st.error(
                                    "**⚠️ Fragilidades conhecidas:** "
                                    + "; ".join(cfg["known_weaknesses"])
                                )
                        st.divider()

                    st.write("**🔗 Relações na rede local**")
                    asset_relations = api("get", f"/api/assets/{a['id']}/relations")
                    if isinstance(asset_relations, list) and asset_relations:
                        for rel in asset_relations:
                            direction = (
                                f"{rel.get('source_asset_name')} → {rel.get('target_asset_name')}"
                            )
                            details = ""
                            if rel.get("protocol") or rel.get("port"):
                                details = f" ({rel.get('protocol') or '—'}:{rel.get('port') or '—'})"
                            st.markdown(
                                f"- `{rel.get('relation_type')}` {direction}{details}"
                            )
                            if rel.get("description"):
                                st.caption(rel["description"])
                            if st.button("Remover relação", key=f"delrel_{a['id']}_{rel['id']}"):
                                api("delete", f"/api/asset-relations/{rel['id']}")
                                st.rerun()
                    else:
                        st.caption("Sem relações registadas.")

                    other_assets = [other for other in assets if other["id"] != a["id"]]
                    if other_assets:
                        with st.form(f"relation_form_{a['id']}"):
                            st.caption("Adicionar ligação a outro activo")
                            target = st.selectbox(
                                "Activo destino",
                                other_assets,
                                format_func=lambda item: (
                                    f"{item['name']} — {item.get('ip_address') or 'sem IP'}"
                                ),
                            )
                            rc1, rc2, rc3 = st.columns(3)
                            relation_type = rc1.selectbox(
                                "Relação",
                                [
                                    "connected_to", "depends_on", "protects", "routes_to",
                                    "hosted_on", "connected_via", "communicates_with", "other",
                                ],
                            )
                            protocol = rc2.text_input("Protocolo")
                            port = rc3.number_input("Porta", min_value=0, max_value=65535, value=0)
                            network_zone = st.text_input("Zona de rede", placeholder="LAN, DMZ, Wi-Fi...")
                            relation_description = st.text_input("Descrição da ligação")
                            save_relation = st.form_submit_button("🔗 Associar activos")
                        if save_relation:
                            result = api(
                                "post",
                                f"/api/assets/{a['id']}/relations",
                                json={
                                    "target_asset_id": target["id"],
                                    "relation_type": relation_type,
                                    "protocol": protocol or None,
                                    "port": port or None,
                                    "network_zone": network_zone or None,
                                    "description": relation_description or None,
                                },
                            )
                            if "error" in result:
                                st.error(result["error"])
                            else:
                                st.success("Relação criada.")
                                st.rerun()

                    st.divider()
                    asset_incs = api("get", f"/api/assets/{a['id']}/incidents")
                    if isinstance(asset_incs, list) and asset_incs:
                        st.write(f"**🚨 Alertas associados ({len(asset_incs)}):**")
                        for ic in asset_incs:
                            st.markdown(
                                f"- {sev_icon(ic.get('severity'))} "
                                f"[{ic['incident_id']}] {ic.get('title', '—')} "
                                f"— {status_label(ic.get('status', ''))}"
                            )
                    else:
                        st.caption("Sem alertas associados a este ativo.")

                    if st.button("🗑️ Remover Ativo", key=f"del_{a['id']}"):
                        api("delete", f"/api/assets/{a['id']}")
                        st.rerun()
        elif isinstance(assets, dict) and "error" in assets:
            st.error(assets["error"])
        else:
            st.info("Nenhum ativo encontrado. Adicione o primeiro ativo.")

    with act_tabs[1]:
        st.subheader("Topologia da Rede Local")
        topology = api("get", "/api/network/topology")
        if isinstance(topology, dict) and "nodes" in topology:
            nodes = topology["nodes"]
            edges = topology.get("edges", [])
            tc1, tc2 = st.columns(2)
            tc1.metric("Nós activos", len(nodes))
            tc2.metric("Relações activas", len(edges))
            if edges:
                st.write("**Ligações conhecidas**")
                for edge in edges:
                    extra = []
                    if edge.get("protocol"):
                        extra.append(edge["protocol"])
                    if edge.get("port"):
                        extra.append(f"porta {edge['port']}")
                    if edge.get("network_zone"):
                        extra.append(edge["network_zone"])
                    suffix = f" — {', '.join(extra)}" if extra else ""
                    st.markdown(
                        f"`{edge['source_asset_name']}` **{edge['relation_type']}** "
                        f"`{edge['target_asset_name']}`{suffix}"
                    )
            else:
                st.info("Ainda não existem relações. Crie-as na lista de activos.")
        elif isinstance(topology, dict) and "error" in topology:
            st.error(topology["error"])

    with act_tabs[2]:
        st.subheader("Adicionar Novo Ativo")
        with st.form("asset_form"):
            a_name = st.text_input("Nome do Ativo *")
            c1, c2 = st.columns(2)
            a_type = c1.selectbox(
                "Tipo *",
                ["server", "workstation", "router", "switch", "firewall", "iot", "other"],
            )
            a_crit = c2.selectbox("Criticidade *", ["CRITICO", "ALTO", "MEDIO", "BAIXO"])
            c1b, c2b = st.columns(2)
            a_ip = c1b.text_input("Endereço IP")
            a_mac = c2b.text_input("MAC Address")
            c1c, c2c = st.columns(2)
            a_host = c1c.text_input("Hostname")
            a_os = c2c.text_input("Sistema Operativo")
            c1d, c2d = st.columns(2)
            a_dept = c1d.text_input("Departamento")
            a_owner = c2d.text_input("Responsável")
            a_loc = st.text_input("Localização Física")
            a_desc = st.text_area("Descrição")
            a_tags_raw = st.text_input("Tags (separadas por vírgula)")
            save_btn = st.form_submit_button("💾 Guardar Ativo", use_container_width=True)

        if save_btn:
            if not a_name.strip():
                st.error("O nome do ativo é obrigatório.")
            else:
                tags = [t.strip() for t in a_tags_raw.split(",") if t.strip()]
                res = api("post", "/api/assets", json={
                    "name": a_name, "asset_type": a_type, "criticality": a_crit,
                    "ip_address": a_ip or None, "mac_address": a_mac or None,
                    "hostname": a_host or None, "os_system": a_os or None,
                    "department": a_dept or None, "owner": a_owner or None,
                    "location": a_loc or None, "description": a_desc or None,
                    "tags": tags,
                })
                if "error" in res:
                    st.error(res["error"])
                else:
                    st.success(f"✅ Ativo **{a_name}** criado com ID {res['id']}")


# ================================================================== #
# TAB 3 — Playbooks
# ================================================================== #
with tabs[2]:
    st.header("📋 Playbooks de Resposta a Incidentes")

    pb_tabs = st.tabs(["📚 Biblioteca", "✨ Gerar com IA", "🗄️ Base de Dados"])

    with pb_tabs[0]:
        st.write("Biblioteca de playbooks pré-definidos (RAG corpus).")
        library = api("get", "/api/playbooks/library")
        if isinstance(library, list):
            for pb in library:
                with st.expander(
                    f"**{pb['name']}** [{pb['id']}] — {pb.get('threat_type', '').title()}"
                ):
                    if pb.get("priority_actions"):
                        st.write("**⚡ Ações Prioritárias:**")
                        for pa in pb["priority_actions"]:
                            st.markdown(f"- 🔴 {pa}")
                    st.write("**📋 Passos:**")
                    for step in pb.get("steps", []):
                        st.markdown(f"- {step}")
                    if pb.get("tags"):
                        st.write("Tags: " + " ".join(f"`{t}`" for t in pb["tags"]))

    with pb_tabs[1]:
        st.subheader("Gerar Playbook Personalizado (RAG + GPT-4o-mini)")
        with st.form("pb_gen_form"):
            pb_desc = st.text_area("Descrição do Incidente *", height=100)
            c1, c2 = st.columns(2)
            pb_type = c1.selectbox(
                "Tipo de Ameaça",
                ["malware", "phishing", "ransomware", "intrusion", "ddos",
                 "data_exfiltration", "account_compromise"],
            )
            pb_sev = c2.selectbox("Severidade", ["CRITICA", "ALTA", "MEDIA", "BAIXA"])
            pb_ctx = st.text_input("Contexto do Ativo Afetado (opcional)")
            gen_btn = st.form_submit_button("⚡ Gerar Playbook", use_container_width=True)

        if gen_btn:
            if not pb_desc.strip():
                st.error("A descrição é obrigatória.")
            else:
                with st.spinner("A gerar playbook com RAG + IA..."):
                    result = api("post", "/api/playbooks/generate", json={
                        "incident_description": pb_desc,
                        "threat_type": pb_type,
                        "severity": pb_sev,
                        "asset_context": pb_ctx or None,
                    })
                if "error" in result:
                    st.error(result["error"])
                else:
                    st.success(f"✅ Playbook gerado: **{result.get('name', '—')}**")
                    if result.get("priority_actions"):
                        st.write("**⚡ Ações Prioritárias:**")
                        for pa in result["priority_actions"]:
                            st.markdown(f"- 🔴 {pa}")
                    st.write("**📋 Passos:**")
                    for step in result.get("steps", []):
                        st.markdown(f"- {step}")
                    if result.get("estimated_time"):
                        st.info(f"⏱️ Tempo estimado: {result['estimated_time']}")
                    if result.get("escalation_criteria"):
                        st.warning(f"📢 Escalada: {result['escalation_criteria']}")
                    if result.get("retrieved_references"):
                        st.caption(f"Baseado em: {', '.join(result['retrieved_references'])}")

    with pb_tabs[2]:
        db_pbs = api("get", "/api/playbooks")
        all_pbs = db_pbs if isinstance(db_pbs, list) else []
        if all_pbs:
            n_generated = sum(1 for p in all_pbs if p.get("is_generated"))
            st.write(
                f"**{len(all_pbs)} playbook(s) na base de dados** "
                f"({len(all_pbs) - n_generated} pré-definidos, {n_generated} gerados por IA):"
            )
            for pb in sorted(all_pbs, key=lambda p: p.get("usage_count", 0), reverse=True):
                origin = "🤖 Gerado por IA" if pb.get("is_generated") else "📌 Base"
                with st.expander(
                    f"**{pb['name']}** [{pb.get('playbook_id', '—')}] — {pb.get('threat_type', '')} "
                    f"| {pb.get('severity_level', '')} | {origin} | usos: {pb.get('usage_count', 0)}"
                ):
                    if pb.get("priority_actions"):
                        st.write("**⚡ Ações Prioritárias:**")
                        for pa in pb["priority_actions"]:
                            st.markdown(f"- 🔴 {pa}")
                    st.write("**📋 Passos:**")
                    for step in pb.get("steps", []):
                        st.markdown(f"- {step}")
        else:
            st.info("Nenhum playbook na base de dados ainda.")


# ================================================================== #
# TAB 4 — XAI / HITL
# ================================================================== #
with tabs[3]:
    st.header("🔬 XAI + Human-in-the-Loop (L4)")

    xai_tabs = st.tabs(["⏳ Fila de Revisão", "✅ Revisões Concluídas", "📈 Estatísticas"])

    with xai_tabs[0]:
        pending = api("get", "/api/hitl/pending")
        if isinstance(pending, list) and pending:
            st.warning(f"**{len(pending)} alerta(s) aguardam revisão do analista**")
            for review in pending:
                inc_id = review["incident_id"]
                score = review.get("anomaly_score", 0)
                sla = review.get("sla_minutes", 30)

                with st.expander(
                    f"🔴 **{inc_id}** | Score ML: {score:.2f} | SLA: {sla}min "
                    f"| {review.get('alert_type', '—')} ({review.get('severity', '—')})"
                ):
                    xai = review.get("xai_report", {})

                    st.write("**📍 Caminho de Decisão (XAI):**")
                    for step in xai.get("decision_path", []):
                        st.write(f"  {step}")

                    risks = review.get("risk_factors", [])
                    if risks:
                        st.write("**⚠️ Fatores de Risco:**")
                        for r in risks:
                            st.markdown(f"- 🔺 {r}")

                    factors = xai.get("top_contributing_factors", [])
                    if factors:
                        st.write("**🔍 Features ML Mais Relevantes:**")
                        for f in factors:
                            imp = {"alto": "🔴", "médio": "🟡", "baixo": "🟢"}.get(
                                f.get("impact", ""), "⚪"
                            )
                            st.write(f"  {imp} {f['description']}")

                    st.write(f"**💡 Recomendação:** {review.get('recommended_action', '—')}")
                    st.write(f"**📝 Resumo:** {xai.get('human_readable_summary', '—')}")
                    st.divider()

                    with st.form(f"rev_{inc_id}"):
                        analyst = st.text_input("Analista (username)")
                        decision = st.radio(
                            "Decisão",
                            ["VERDADEIRO_POSITIVO", "FALSO_POSITIVO", "ESCALAR"],
                            horizontal=True,
                        )
                        notes = st.text_area("Notas do Analista")
                        rev_btn = st.form_submit_button("✅ Submeter Revisão", use_container_width=True)

                    if rev_btn:
                        if not analyst.strip():
                            st.error("Username do analista é obrigatório.")
                        else:
                            res = api("post", f"/api/hitl/{inc_id}/review", json={
                                "analyst_username": analyst,
                                "decision": decision,
                                "notes": notes,
                            })
                            if "error" in res:
                                st.error(res["error"])
                            else:
                                sla_ok = "✅ Dentro do SLA" if res.get("met_sla") else "⚠️ SLA excedido"
                                st.success(
                                    f"Revisão submetida em {res.get('review_time_minutes', 0):.1f}min — {sla_ok}"
                                )
                                st.rerun()
        elif isinstance(pending, dict) and "error" in pending:
            st.error(pending["error"])
        else:
            st.success("✅ Nenhuma alerta pendente de revisão humana.")

    with xai_tabs[1]:
        completed = api("get", "/api/hitl/completed")
        if isinstance(completed, list) and completed:
            for r in completed:
                dec_icon = {
                    "VERDADEIRO_POSITIVO": "🔴",
                    "FALSO_POSITIVO": "✅",
                    "ESCALAR": "⬆️",
                }.get(r.get("decision", ""), "⚪")
                sla_tag = "✅ SLA" if r.get("met_sla") else "⚠️ SLA excedido"
                st.write(
                    f"{dec_icon} **{r['incident_id']}** — {r.get('decision', '—')} "
                    f"por *{r.get('analyst_username', '—')}* "
                    f"({r.get('review_time_minutes', 0):.1f}min — {sla_tag})"
                )
                if r.get("analyst_notes"):
                    st.caption(f"  📝 {r['analyst_notes']}")
        else:
            st.info("Sem revisões concluídas ainda.")

    with xai_tabs[2]:
        stats = api("get", "/api/hitl/stats")
        if isinstance(stats, dict) and "total_reviewed" in stats:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total Revistas", stats["total_reviewed"])
            c2.metric("Pendentes", stats["pending_count"])
            c3.metric("Tempo Médio", f"{stats.get('avg_review_time_min', 0):.1f}min")
            c4.metric("Compliance SLA", f"{stats.get('sla_compliance_pct', 0):.1f}%")
        else:
            st.info("Sem dados estatísticos ainda.")


# ================================================================== #
# TAB 5 — Gamificação
# ================================================================== #
with tabs[4]:
    st.header("🎮 Plataforma de Formação & Gamificação (L5)")

    gam_tabs = st.tabs(["🎯 Missões", "🏆 Leaderboard", "👤 Utilizadores", "🤖 Gerar Cenário", "🚩 Reportar Email"])

    with gam_tabs[0]:
        diff_f = st.selectbox(
            "Dificuldade",
            ["Todas", "INICIANTE", "INTERMEDIO", "AVANCADO"],
            key="diff_filter",
        )
        scenarios = api(
            "get", "/api/gamification/scenarios",
            params={"difficulty": diff_f if diff_f != "Todas" else None},
        )

        diff_icons = {"INICIANTE": "🟢", "INTERMEDIO": "🟡", "AVANCADO": "🔴"}

        if isinstance(scenarios, list) and scenarios:
            for sc in scenarios:
                diff = sc.get("difficulty", "INTERMEDIO")
                d_icon = diff_icons.get(diff, "⚪")
                questions = sc.get("questions", [])
                with st.expander(
                    f"{d_icon} **{sc['title']}** | {diff} | ⭐ {sc.get('xp_reward', 0)} XP "
                    f"| {len(questions)} questão(ões)"
                ):
                    st.write(sc.get("description", ""))
                    st.caption(f"Tipo: {sc.get('type', '—')}")

                    users_list = api("get", "/api/users")
                    user_options = users_list if isinstance(users_list, list) else []
                    if user_options:
                        sel_user = st.selectbox(
                            "Jogar como:",
                            options=user_options,
                            format_func=lambda u: f"{u.get('full_name', u['username'])} (Nível {u.get('level', 1)})",
                            key=f"user_sel_{sc['id']}",
                        )
                        user_id = sel_user["id"] if sel_user else 1
                    else:
                        user_id = st.number_input("ID do utilizador", min_value=1, key=f"uid_{sc['id']}")

                    answers = []
                    with st.form(f"mission_{sc['id']}"):
                        for qi, q in enumerate(questions):
                            ans = st.radio(
                                f"**Q{qi + 1}. {q['question']}**",
                                options=list(range(len(q["options"]))),
                                format_func=lambda x, q=q: q["options"][x],
                                key=f"q_{sc['id']}_{qi}",
                            )
                            answers.append(ans)
                        play_btn = st.form_submit_button(
                            "🎯 Submeter Respostas", use_container_width=True
                        )

                    if play_btn:
                        result = api(
                            "post",
                            f"/api/gamification/scenarios/{sc['id']}/submit",
                            json={"user_id": int(user_id), "answers": answers},
                        )
                        if "error" in result:
                            st.error(result["error"])
                        else:
                            score = result.get("score_percentage", 0)
                            xp = result.get("xp_earned", 0)
                            if result.get("passed"):
                                st.success(f"✅ {result['feedback']} | +{xp} XP")
                            else:
                                st.error(f"❌ {result['feedback']}")
                            st.progress(int(score), text=f"Pontuação: {score:.1f}%")

                            with st.expander("📖 Explicações"):
                                for fb in result.get("detailed_feedback", []):
                                    icon = "🟢" if fb["is_correct"] else "🔴"
                                    st.write(f"{icon} **{fb['question']}**")
                                    st.write(f"  Sua resposta: *{fb['your_answer']}*")
                                    if not fb["is_correct"]:
                                        st.write(f"  Correta: **{fb['correct_answer']}**")
                                    st.caption(f"  {fb['explanation']}")

                            if result.get("new_badges"):
                                for badge in result["new_badges"]:
                                    st.balloons()
                                    st.success(f"🏅 Novo badge: **{badge}**!")
                            st.info(
                                f"XP Total: {result.get('new_xp_total', 0)} | "
                                f"Nível: {result.get('new_level', 1)} | "
                                f"Risk Score: {result.get('new_risk_score', 0):.1f}"
                            )
        else:
            st.info("Sem cenários disponíveis.")

    with gam_tabs[1]:
        st.subheader("🏆 Tabela de Classificação")
        lb = api("get", "/api/gamification/leaderboard")
        if isinstance(lb, list) and lb:
            rank_icons = {1: "🥇", 2: "🥈", 3: "🥉"}
            header = st.columns([0.5, 2, 1, 1, 1.5, 1.5])
            header[0].write("**Pos.**")
            header[1].write("**Nome**")
            header[2].write("**Nível**")
            header[3].write("**XP**")
            header[4].write("**Missões**")
            header[5].write("**Risk Score**")
            st.divider()
            for u in lb:
                rank = u.get("rank", 0)
                r_icon = rank_icons.get(rank, f"#{rank}")
                risk = u.get("risk_score", 50)
                r_color = "🟢" if risk < 30 else "🟡" if risk < 60 else "🔴"
                row = st.columns([0.5, 2, 1, 1, 1.5, 1.5])
                row[0].write(r_icon)
                row[1].write(u.get("full_name", u.get("username", "—")))
                row[2].write(f"⭐ {u.get('level', 1)}")
                row[3].write(f"{u.get('xp_points', 0)} XP")
                row[4].write(f"{u.get('missions_completed', 0)}/{u.get('total_missions', 0)}")
                row[5].write(f"{r_color} {risk:.0f}")
        else:
            st.info("Sem utilizadores na classificação.")

    with gam_tabs[2]:
        st.subheader("👤 Utilizadores")

        user_asset_options = api("get", "/api/assets", params={})
        user_asset_list = user_asset_options if isinstance(user_asset_options, list) else []
        user_asset_choices = ["— Nenhum —"] + [
            f"{a['name']} — {a.get('ip_address') or 's/ IP'} [{a.get('criticality') or '—'}]"
            for a in user_asset_list
        ]

        users_all = api("get", "/api/users")
        if isinstance(users_all, list) and users_all:
            for u in users_all:
                risk = u.get("risk_score", 50)
                r_color = "🟢" if risk < 30 else "🟡" if risk < 60 else "🔴"
                with st.expander(
                    f"**{u.get('full_name', u['username'])}** "
                    f"({u.get('role', '—')}) | Nível {u.get('level', 1)} | "
                    f"{r_color} Risk: {risk:.0f}"
                ):
                    c1, c2, c3 = st.columns(3)
                    c1.metric("XP", u.get("xp_points", 0))
                    c2.metric("Missões", f"{u.get('missions_completed', 0)}/{u.get('total_missions', 0)}")
                    c3.metric("Departamento", u.get("department") or "—")
                    st.write(f"**Ativo Associado:** {u.get('asset_name') or '—'}")
                    st.progress(int(risk), text=f"Human Risk Score: {risk:.1f}/100")
                    badges = u.get("badges", [])
                    if badges:
                        st.write("Badges: " + " ".join(f"`{b}`" for b in badges))

                    edit_key = f"editing_user_{u['id']}"
                    if st.button("✏️ Editar Utilizador", key=f"edit_btn_{u['id']}"):
                        st.session_state[edit_key] = not st.session_state.get(edit_key, False)

                    if st.session_state.get(edit_key):
                        current_asset_idx = 0
                        if u.get("asset_id"):
                            for i, a in enumerate(user_asset_list):
                                if a["id"] == u["asset_id"]:
                                    current_asset_idx = i + 1
                                    break

                        role_options = ["employee", "soc_analyst", "manager", "admin"]
                        with st.form(f"edit_user_form_{u['id']}"):
                            eu_username = st.text_input("Username *", value=u.get("username", ""))
                            ce1, ce2 = st.columns(2)
                            eu_name = ce1.text_input("Nome Completo", value=u.get("full_name") or "")
                            eu_email = ce2.text_input("Email", value=u.get("email") or "")
                            ce3, ce4 = st.columns(2)
                            eu_role = ce3.selectbox(
                                "Role", role_options,
                                index=role_options.index(u.get("role")) if u.get("role") in role_options else 0,
                            )
                            eu_dept = ce4.text_input("Departamento", value=u.get("department") or "")
                            eu_asset_choice = st.selectbox(
                                "Ativo Associado", user_asset_choices, index=current_asset_idx,
                            )
                            save_edit_btn = st.form_submit_button("💾 Guardar Alterações", use_container_width=True)

                        if save_edit_btn:
                            if not eu_username.strip():
                                st.error("O username é obrigatório.")
                            else:
                                edit_payload = {
                                    "username": eu_username, "full_name": eu_name,
                                    "email": eu_email, "role": eu_role, "department": eu_dept,
                                    "asset_id": None,
                                }
                                if eu_asset_choice != user_asset_choices[0]:
                                    sel_idx = user_asset_choices.index(eu_asset_choice) - 1
                                    edit_payload["asset_id"] = user_asset_list[sel_idx]["id"]

                                res = api("put", f"/api/users/{u['id']}", json=edit_payload)
                                if "error" in res:
                                    st.error(res.get("error", "Erro ao atualizar utilizador"))
                                else:
                                    st.session_state[edit_key] = False
                                    st.success(f"✅ Utilizador '{eu_username}' atualizado")
                                    st.rerun()

        st.divider()
        st.subheader("➕ Criar Utilizador")

        with st.form("user_form"):
            u_username = st.text_input("Username *")
            c1, c2 = st.columns(2)
            u_name = c1.text_input("Nome Completo")
            u_email = c2.text_input("Email")
            c3, c4 = st.columns(2)
            u_role = c3.selectbox("Role", ["employee", "soc_analyst", "manager", "admin"])
            u_dept = c4.text_input("Departamento")
            u_asset_choice = st.selectbox("Ativo Associado", user_asset_choices)
            create_btn = st.form_submit_button("Criar Utilizador", use_container_width=True)

        if create_btn:
            if not u_username.strip():
                st.error("O username é obrigatório.")
            else:
                payload = {
                    "username": u_username, "full_name": u_name,
                    "email": u_email, "role": u_role, "department": u_dept,
                }
                if u_asset_choice != user_asset_choices[0]:
                    sel_idx = user_asset_choices.index(u_asset_choice) - 1
                    payload["asset_id"] = user_asset_list[sel_idx]["id"]

                res = api("post", "/api/users", json=payload)
                if "error" in res:
                    st.error(res.get("error", "Erro ao criar utilizador"))
                else:
                    st.success(f"✅ Utilizador '{u_username}' criado com ID {res['id']}")

    with gam_tabs[3]:
        st.subheader("🤖 Gerar Cenário de Treino com IA")
        st.info("Gera automaticamente cenários gamificados baseados em incidentes reais.")
        with st.form("gen_sc_form"):
            gs_inc = st.text_input("ID do Incidente (ex: INC-20250607-ABC123)")
            c1, c2 = st.columns(2)
            gs_type = c1.selectbox(
                "Tipo",
                ["malware", "phishing", "ransomware", "intrusion", "ddos", "social_engineering"],
            )
            gs_sev = c2.selectbox("Severidade", ["ALTA", "CRITICA", "MEDIA", "BAIXA"])
            gs_desc = st.text_area("Descrição resumida (sem dados sensíveis)", height=80)
            gen_sc_btn = st.form_submit_button("🎲 Gerar Cenário", use_container_width=True)

        if gen_sc_btn:
            with st.spinner("A gerar cenário com IA..."):
                sc = api("post", "/api/gamification/scenarios/generate", json={
                    "incident_id": gs_inc or "INC-MANUAL",
                    "incident_type": gs_type,
                    "severity": gs_sev,
                    "description": gs_desc,
                })
            if "error" in sc:
                st.error(sc["error"])
            else:
                st.success(f"✅ Cenário: **{sc.get('title', '—')}**")
                st.write(sc.get("description", ""))
                st.write(
                    f"Dificuldade: **{sc.get('difficulty', '—')}** | "
                    f"XP: **{sc.get('xp_reward', 0)}** | "
                    f"Questões: **{len(sc.get('questions', []))}**"
                )
                with st.expander("Ver Questões"):
                    for qi, q in enumerate(sc.get("questions", [])):
                        st.write(f"**Q{qi + 1}.** {q['question']}")
                        for oi, opt in enumerate(q.get("options", [])):
                            mark = "✅ " if oi == q.get("correct") else "  "
                            st.write(f"  {mark}{opt}")
                        st.caption(f"  Explicação: {q.get('explanation', '')}")
                st.info("Cenário adicionado à plataforma — já aparece na tab Missões.")

    with gam_tabs[4]:
        st.subheader("🚩 Reportar Email Suspeito")
        st.caption(
            "Modelo Cofense/PhishMe: o colaborador reporta um email real (não uma simulação) "
            "com um clique. O sistema faz triagem automática e — se a ameaça for provável — "
            "gera de imediato um incidente real no SOCHAI. Fecha o ciclo na direção contrária "
            "à habitual: além do SOCHAI alimentar a formação (L1 → L5), a formação/colaborador "
            "passa também a alimentar o SOCHAI (L5 → L1)."
        )

        users_list_report = api("get", "/api/users")
        report_user_options = users_list_report if isinstance(users_list_report, list) else []
        if report_user_options:
            report_sel_user = st.selectbox(
                "Reportar como:",
                options=report_user_options,
                format_func=lambda u: f"{u.get('full_name', u['username'])} (Nível {u.get('level', 1)})",
                key="report_user_sel",
            )
            report_user_id = report_sel_user["id"] if report_sel_user else 1
        else:
            report_user_id = st.number_input("ID do utilizador", min_value=1, key="report_uid")

        with st.form("phishing_report_form"):
            rp_sender = st.text_input(
                "Remetente *", placeholder="suporte@microsoft-helpdesk.net"
            )
            c1, c2 = st.columns(2)
            rp_subject = c1.text_input(
                "Assunto", placeholder="Urgente: verifique a sua conta agora"
            )
            rp_attachment = c2.checkbox("Contém anexo")
            rp_body = st.text_area(
                "Excerto do corpo do email", height=90,
                placeholder="A sua conta será suspensa. Confirme os seus dados para evitar o bloqueio.",
            )
            rp_urls = st.text_area(
                "URLs presentes no email (uma por linha, opcional)", height=60,
                placeholder="https://login.office365-secure.test/renew",
            )
            report_btn = st.form_submit_button("🚩 Reportar ao SOCHAI", use_container_width=True)

        if report_btn:
            if not rp_sender.strip():
                st.error("O remetente é obrigatório.")
            else:
                payload = {
                    "reporter_id": int(report_user_id),
                    "sender": rp_sender,
                    "subject": rp_subject,
                    "body_snippet": rp_body,
                    "urls": [u.strip() for u in rp_urls.splitlines() if u.strip()],
                    "has_attachment": rp_attachment,
                }
                result = api("post", "/api/phishing/report", json=payload)
                if "error" in result:
                    st.error(result["error"])
                else:
                    triage = result.get("triage", {})
                    verdict = triage.get("verdict", "—")
                    verdict_icon = {"malicious": "🔴", "pending": "🟡", "benign": "🟢"}.get(verdict, "⚪")
                    st.success(result.get("message", "Reporte submetido."))

                    st.progress(
                        int(triage.get("threat_score", 0)),
                        text=f"{verdict_icon} Score de ameaça: {triage.get('threat_score', 0):.0f}/100 — veredicto: {verdict}",
                    )
                    if triage.get("signals"):
                        st.caption("Sinais detetados: " + "; ".join(triage["signals"]))

                    if result.get("incident_created"):
                        st.success(
                            f"🔗 **Ciclo L5 → L1 fechado:** incidente **{result['incident_created']}** "
                            f"criado no SOCHAI — visível na tab **SOCHAI Operations**."
                        )

                    c1, c2, c3 = st.columns(3)
                    c1.metric("XP ganho", f"+{result.get('xp_awarded', 0)}")
                    c2.metric("Risk Score", f"{result.get('new_risk_score', 0):.1f}",
                              delta=f"{-result.get('risk_reduction', 0):.1f}")
                    c3.metric("XP total", result.get("new_xp_total", 0))

                    if result.get("new_badges"):
                        for badge in result["new_badges"]:
                            st.balloons()
                            st.success(f"🏅 Novo badge: **{badge}**!")

        st.divider()
        st.subheader("📋 Reportes Recentes — fila de triagem")
        recent_reports = api("get", "/api/phishing/reports", params={"limit": 10})
        if isinstance(recent_reports, list) and recent_reports:
            v_icon = {"malicious": "🔴", "pending": "🟡", "benign": "🟢"}
            for r in recent_reports:
                icon = v_icon.get(r.get("verdict"), "⚪")
                link = f" → `{r['linked_incident_id']}`" if r.get("linked_incident_id") else ""
                st.write(
                    f"{icon} **{r.get('sender', '—')}** — {r.get('subject') or '(sem assunto)'} "
                    f"· reportado por {r.get('reporter', '—')} · score {r.get('threat_score', 0):.0f}"
                    f"{link}"
                )
        else:
            st.info("Ainda não há reportes de phishing.")


# ================================================================== #
# TAB 6 — Analytics
# ================================================================== #
with tabs[5]:
    st.header("📊 Analytics & Métricas SOCHAI")

    ov = api("get", "/api/analytics/overview")
    inc_list = api("get", "/api/incidents", params={"limit": 50})
    users_list_all = api("get", "/api/users")
    campaigns = api("get", "/api/phishing/campaigns")

    if isinstance(ov, dict) and "incidents" in ov:
        inc = ov["incidents"]
        assets_d = ov.get("assets", {})
        users_d = ov.get("users", {})
        hitl_d = ov.get("hitl", {})
        soar_d = ov.get("soar", {})

        recent = inc_list if isinstance(inc_list, list) else []
        users_list = users_list_all if isinstance(users_list_all, list) else []
        avg_risk = users_d.get("avg_risk_score", 0)
        open_crit = sum(
            1 for i in recent
            if (i.get("severity") or "").upper() == "CRITICA"
            and i.get("status") in ("open", "investigating")
        )

        # ---- Overview: overall risk level ----
        if avg_risk >= 60 or open_crit >= 2:
            risk_lv, risk_hex, risk_icon = "ALTO", "#ff5d6c", "🔴"
            banner_txt = (f"{open_crit} incidente(s) crítico(s) em aberto e risco humano elevado. "
                          "Ação imediata necessária.")
        elif avg_risk >= 30 or open_crit >= 1 or (inc.get("open", 0) + inc.get("investigating", 0)) >= 3:
            risk_lv, risk_hex, risk_icon = "MÉDIO", "#f5c451", "🟡"
            banner_txt = ("Há elementos que requerem seguimento mas sem risco crítico imediato. "
                          "Monitorize os incidentes abertos e o risco humano.")
        else:
            risk_lv, risk_hex, risk_icon = "BAIXO", "#2fd07a", "🟢"
            banner_txt = "Situação estável. Continue a investir na formação dos colaboradores."

        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap;
                    border:1px solid {risk_hex}55;border-radius:14px;padding:18px 22px;
                    margin-bottom:20px;background:{risk_hex}11;">
            <div style="font-size:2rem;line-height:1">{risk_icon}</div>
            <div>
                <div style="font-size:15px;font-weight:700;color:{risk_hex};margin-bottom:4px;">
                    Nível de risco geral: {risk_lv}
                </div>
                <div style="color:#8899aa;font-size:13px;">{banner_txt}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # ---- KPIs de desempenho do SOC ----
        kpis = ov.get("kpis") or {}
        st.subheader("⏱️ KPIs de Desempenho do SOC")
        st.caption(
            "Eficiência de deteção e resposta, e precisão dos alertas — a base da "
            "monitorização, medição e relato de serviço (ISO/IEC 20000, 9.1 e 9.4)"
        )

        sla_pct = kpis.get("sla_compliance_pct")
        fp_rate = kpis.get("false_positive_rate_pct")
        sla_color = (
            "" if sla_pct is None
            else "green" if sla_pct >= 90 else "yellow" if sla_pct >= 70 else "red"
        )
        fp_color = (
            "" if fp_rate is None
            else "green" if fp_rate <= 20 else "yellow" if fp_rate <= 40 else "red"
        )

        kpi_rows = [
            [
                ("MTTD", fmt_minutes(kpis.get("mttd_minutes")), "",
                 kpis.get("mttd_note", "por instrumentar")),
                ("MTTI", fmt_minutes(kpis.get("mtti_minutes")), "",
                 f"até à triagem · {kpis.get('investigated_count', 0)} incidente(s)"),
                ("MTTR", fmt_minutes(kpis.get("mttr_minutes")), "",
                 f"até à resolução · {kpis.get('resolved_count', 0)} incidente(s)"),
                ("Dentro do SLA", fmt_pct(sla_pct), sla_color,
                 f"{kpis.get('sla_sample', 0)} incidente(s) resolvido(s)"),
            ],
            [
                ("Falsos Positivos", fmt_pct(fp_rate), fp_color,
                 "dos alertas classificados na triagem"),
                ("Precisão (VP)", fmt_pct(kpis.get("true_positive_rate_pct")), "",
                 "alertas confirmados como ameaça real"),
                ("Alertas / Confirmado",
                 kpis.get("alerts_per_confirmed_incident") or "—", "",
                 "esforço de triagem por ameaça real"),
                ("Alertas Classificados", kpis.get("triaged_count", 0), "",
                 f"de {kpis.get('total_alerts', 0)} alertas recebidos"),
            ],
        ]
        for row in kpi_rows:
            cols = st.columns(4)
            for col, (lbl, val, clr, note) in zip(cols, row):
                col.markdown(metric_card(lbl, val, clr), unsafe_allow_html=True)
                col.caption(note)

        mttr_sev = kpis.get("mttr_by_severity") or {}
        sla_targets = kpis.get("sla_targets_minutes") or {}
        if mttr_sev:
            st.markdown("**MTTR por severidade vs. alvo de SLA**")
            for sev in ("CRITICA", "ALTA", "MEDIA", "BAIXA"):
                actual = mttr_sev.get(sev)
                if actual is None:
                    continue
                target = sla_targets.get(sev)
                within = target is not None and actual <= target
                sc = st.columns([2, 2, 2, 1])
                sc[0].markdown(f"{sev_icon(sev)} **{sev}**")
                sc[1].markdown(f"MTTR: `{fmt_minutes(actual)}`")
                sc[2].markdown(f"Alvo: `{fmt_minutes(target)}`")
                sc[3].markdown("✅" if within else "⚠️")
        elif not kpis.get("resolved_count"):
            st.info(
                "Ainda não há incidentes resolvidos — o MTTR e o cumprimento de SLA "
                "passam a ser calculados assim que fechar incidentes na aba "
                "**SOCHAI Operations**."
            )

        st.divider()

        # ---- Incident metrics ----
        st.subheader("🚨 Incidentes")
        cols = st.columns(6)
        data = [
            ("Total", inc.get("total", 0), ""),
            ("Abertos", inc.get("open", 0), "red"),
            ("Investigação", inc.get("investigating", 0), "yellow"),
            ("Resolvidos", inc.get("resolved", 0), "green"),
            ("True Positive", inc.get("true_positive", 0), "red"),
            ("False Positive", inc.get("false_positive", 0), "green"),
        ]
        for col, (lbl, val, clr) in zip(cols, data):
            col.markdown(metric_card(lbl, val, clr), unsafe_allow_html=True)

        st.divider()

        col_a, col_b = st.columns(2)

        with col_a:
            st.subheader("🖥️ Ativos & Utilizadores")
            ca1, ca2 = st.columns(2)
            ca1.metric("Ativos Registados", assets_d.get("total", 0))
            ca2.metric("Utilizadores", users_d.get("total", 0))
            st.metric("Missões de Formação Concluídas", users_d.get("total_missions_completed", 0))
            r_label = "🟢 Baixo" if avg_risk < 30 else "🟡 Médio" if avg_risk < 60 else "🔴 Alto"
            st.metric("Risk Score Médio da Organização", f"{avg_risk:.1f} ({r_label})")
            st.progress(int(avg_risk), text="Risco organizacional médio (0=seguro, 100=crítico)")

        with col_b:
            st.subheader("🔬 HITL & ⚡ SOAR")
            cb1, cb2 = st.columns(2)
            cb1.metric("Revisões HITL", hitl_d.get("total_reviewed", 0))
            cb2.metric("HITL Pendentes", hitl_d.get("pending_count", 0))
            st.metric("Compliance SLA HITL", f"{hitl_d.get('sla_compliance_pct', 0):.1f}%")
            st.progress(
                int(hitl_d.get("sla_compliance_pct", 0)),
                text=f"SLA Compliance: {hitl_d.get('sla_compliance_pct', 0):.1f}%"
            )
            st.metric("Ações SOAR Executadas", soar_d.get("total_actions", 0))
            st.metric("SOAR Sucesso", soar_d.get("success", 0))

        # ---- Phishing Simulation: Resilience Rate ----
        st.divider()
        st.subheader("🎣 Simulações de Phishing — Resiliência")
        global_resilience = None
        if isinstance(campaigns, list) and campaigns:
            # Agregar métricas de todas as campanhas
            tot_clicked = sum(c["metrics"]["clicked"] for c in campaigns)
            tot_reported = sum(c["metrics"]["reported"] for c in campaigns)
            tot_ignored = sum(c["metrics"]["ignored"] for c in campaigns)
            denom = tot_reported + tot_clicked
            global_resilience = round(tot_reported / denom * 100, 1) if denom else None

            mc = st.columns(4)
            mc[0].metric("Campanhas", len(campaigns))
            mc[1].metric("Cliques na Isca", tot_clicked,
                         help="Quem clicou no link simulado (risco)")
            mc[2].metric("Reportes", tot_reported,
                         help="Quem reportou a simulação (resiliente)")
            if global_resilience is not None:
                rlabel = "🟢 Forte" if global_resilience >= 70 else "🟡 Média" if global_resilience >= 40 else "🔴 Fraca"
                mc[3].metric("Resilience Rate", f"{global_resilience:.1f}%", help="reportes / (reportes + cliques)")
                st.progress(int(global_resilience),
                            text=f"Resiliência organizacional: {global_resilience:.1f}% ({rlabel})")
            else:
                mc[3].metric("Resilience Rate", "—")

            # Tabela por campanha
            st.markdown("**Detalhe por campanha**")
            rows = []
            for c in campaigns:
                m = c["metrics"]
                rr = m.get("resilience_rate_pct")
                rows.append({
                    "Campanha": c["name"],
                    "Dificuldade": c["difficulty"],
                    "Alvos": m["total_targets"],
                    "Cliques": m["clicked"],
                    "Reportes": m["reported"],
                    "Ignorados": m["ignored"],
                    "Click Rate": f"{m['click_rate_pct']:.0f}%",
                    "Resiliência": f"{rr:.0f}%" if rr is not None else "—",
                })
            st.dataframe(rows, use_container_width=True, hide_index=True)
        else:
            st.info("Ainda não há campanhas de simulação. Lance uma na aba Gamificação.")

        # ---- SOAR log ----
        st.divider()
        st.subheader("⚡ SOAR — Últimas Ações Executadas")
        soar_log = api("get", "/api/soar/log")
        if isinstance(soar_log, list) and soar_log:
            for entry in reversed(soar_log[-10:]):
                st.write(
                    f"✅ **{entry.get('action_name', '—')}** "
                    f"[{entry.get('incident_id', '—')}] "
                    f"— {(entry.get('executed_at') or '')[:16]}"
                )
                st.caption(f"  {entry.get('message', '')}")
        else:
            st.info("Nenhuma ação SOAR registada ainda.")

        # ---- Risco Humano por Departamento ----
        st.divider()
        st.subheader("🧑‍🤝‍🧑 Risco Humano por Departamento")
        st.caption("Detalhe por equipa do Risk Score médio da organização, mostrado acima")

        dept_risk: Dict[str, List[float]] = {}
        for u in users_list:
            dept = u.get("department") or "Sem departamento"
            dept_risk.setdefault(dept, []).append(float(u.get("risk_score") or 0))

        if dept_risk:
            dept_avg = {d: sum(v) / len(v) for d, v in dept_risk.items()}
            for dept, score in sorted(dept_avg.items(), key=lambda x: x[1], reverse=True):
                s = int(score)
                c_hex = "#ff5d6c" if s >= 60 else "#f5c451" if s >= 30 else "#2fd07a"
                lbl_dept = "🔴 Alto" if s >= 60 else "🟡 Médio" if s >= 30 else "🟢 Baixo"
                n_dept = len(dept_risk[dept])
                dc1, dc2 = st.columns([3, 1])
                dc1.markdown(
                    f'<div style="font-size:13px;margin-bottom:2px">'
                    f'<b>{dept}</b> '
                    f'<span style="color:#5d6f90;font-size:11px">({n_dept} col.)</span></div>',
                    unsafe_allow_html=True,
                )
                dc1.progress(s, text=f"HRS: {s}/100")
                dc2.markdown(
                    f'<div style="padding-top:20px;font-size:12px;font-weight:700;color:{c_hex}">'
                    f'{lbl_dept}</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.info("Sem dados de utilizadores por departamento.")

        # ---- Colaboradores prioritários para formação ----
        st.subheader("🎓 Colaboradores Prioritários para Formação")
        trained = sum(1 for u in users_list if u.get("missions_completed", 0) > 0)
        trained_pct = int(trained / len(users_list) * 100) if users_list else 0
        st.caption(f"Pessoal formado: {trained_pct}% ({trained}/{len(users_list)}) · HRS ≥ 50 tem prioridade")

        high_risk_users = sorted(
            [u for u in users_list if (u.get("risk_score") or 0) >= 50],
            key=lambda x: x.get("risk_score", 0), reverse=True,
        )[:5]
        if high_risk_users:
            for u in high_risk_users:
                rs = u.get("risk_score", 0)
                c_u = "#ff5d6c" if rs >= 60 else "#f5c451"
                st.markdown(
                    f'<div style="display:flex;align-items:center;gap:10px;'
                    f'padding:6px 0;border-bottom:1px solid #22304d;">'
                    f'<span style="font-size:13px;flex:1">'
                    f'<b>{u.get("full_name") or u.get("username", "—")}</b>'
                    f' · {u.get("department") or "—"}</span>'
                    f'<span style="font-family:monospace;font-size:12px;color:{c_u};font-weight:700">'
                    f'HRS {int(rs)}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.success("Nenhum colaborador com risco elevado (HRS ≥ 50).")

        # ---- Alertas ativos — leitura para gestão ----
        st.divider()
        st.subheader("🔔 Alertas Ativos — Leitura para Gestão")
        st.caption("Tradução em linguagem não técnica dos incidentes em aberto ou em investigação")

        THREAT_BIZ = {
            "malware": (
                "Software malicioso encontrado num equipamento da empresa",
                "Um computador foi infetado com um programa criado para causar dano. "
                "Pode destruir ficheiros, roubar informação ou abrir caminho para ataques maiores.",
                "⚠️ Risco operacional: produtividade afetada; dados da empresa e clientes em risco.",
                "A equipa de TI está a isolar o equipamento e a eliminar a ameaça.",
            ),
            "phishing": (
                "Tentativa de burla por email identificada",
                "Alguém tentou enganar colaboradores da empresa com um email falso para roubar "
                "passwords ou informação confidencial — como um pescador a lançar o anzol.",
                "⚠️ Se um colaborador respondeu ou clicou no link, terceiros podem já ter acesso "
                "às nossas contas e sistemas.",
                "A equipa de TI está a verificar se alguém 'mordeu o anzol' e a proteger as contas em risco.",
            ),
            "ransomware": (
                "Possível ataque de bloqueio e pedido de resgate",
                "Os nossos sistemas podem estar a ser bloqueados por criminosos que exigem um "
                "pagamento para os libertar. É o tipo de ataque mais devastador que uma organização pode sofrer.",
                "🚨 Pode causar paragem total das operações durante dias ou semanas, com custos "
                "muito elevados de recuperação e exposição de dados de clientes.",
                "Ação de emergência em curso: a equipa de TI está a conter o ataque e a verificar "
                "se os backups estão intactos.",
            ),
            "intrusion": (
                "Acesso não autorizado aos sistemas da empresa detetado",
                "Uma pessoa não autorizada entrou na nossa rede ou sistemas — como se alguém tivesse "
                "entrado no escritório sem chave e sem ser visto.",
                "⚠️ Informação confidencial pode ter sido acedida. Quanto mais tempo a situação "
                "se prolongar, maior o potencial dano.",
                "A equipa de TI está a identificar como entraram e a expulsar o intruso.",
            ),
            "ddos": (
                "Serviços da empresa sob ataque de sobrecarga",
                "Os nossos sistemas estão a receber um volume artificial e enorme de pedidos para "
                "os tornar inacessíveis — como bloquear propositadamente a porta de entrada da empresa.",
                "⚠️ Clientes, fornecedores e colaboradores podem não conseguir aceder aos nossos "
                "serviços enquanto durar o ataque.",
                "A equipa de TI está a ativar filtros para bloquear o tráfego malicioso e restaurar "
                "o acesso normal.",
            ),
            "data_exfiltration": (
                "Suspeita de fuga de dados confidenciais para o exterior",
                "Informação da empresa ou de clientes pode estar a ser copiada e enviada para fora "
                "sem autorização — como alguém a fotocopiar documentos sigilosos e a levá-los consigo.",
                "🚨 Obrigação legal de notificar a CNPD (proteção de dados). Risco de coimas "
                "significativas ao abrigo do RGPD, dano reputacional e perda de confiança dos clientes.",
                "A equipa de TI está a identificar que dados foram afetados. Pode ser necessário "
                "notificar as autoridades e comunicar aos clientes.",
            ),
            "brute_force": (
                "Tentativas forçadas de acesso a contas da empresa",
                "Alguém está a tentar entrar automaticamente nas nossas contas, experimentando "
                "milhares de passwords — como alguém a experimentar todas as combinações possíveis "
                "de um cadeado.",
                "⚠️ Se conseguir entrar, o atacante pode aceder a emails, sistemas financeiros "
                "ou dados de clientes.",
                "A equipa de TI está a bloquear o atacante e a reforçar a proteção das contas.",
            ),
            "account_compromise": (
                "Conta de colaborador possivelmente controlada por terceiros",
                "Uma conta de acesso à empresa pode estar nas mãos de alguém de fora — como se "
                "um estranho tivesse as chaves do escritório com o nome de um colaborador.",
                "⚠️ O atacante pode enviar emails em nome da empresa, aceder a informação "
                "confidencial e realizar operações não autorizadas.",
                "A equipa de TI está a bloquear a conta e a investigar que ações foram realizadas.",
            ),
            "scan": (
                "Entidade externa a explorar os nossos sistemas",
                "Alguém está a sondar os nossos sistemas a partir do exterior, à procura de pontos "
                "fracos — como um ladrão a observar o edifício antes de tentar entrar.",
                "ℹ️ Pode ser o prenúncio de um ataque mais sério. A empresa está no radar de um "
                "potencial atacante.",
                "A equipa de TI está a monitorizar a situação e a reforçar as defesas preventivamente.",
            ),
            "other": (
                "Situação de segurança anómala detetada",
                "Os nossos sistemas identificaram algo suspeito que foge ao padrão normal de "
                "funcionamento da empresa.",
                "ℹ️ Pode ser uma ameaça real ou um falso alarme. A equipa de TI está a investigar.",
                "A equipa de TI está a analisar a situação e irá atualizar o estado brevemente.",
            ),
        }

        SEV_PILL = {
            "CRITICA": '<span style="background:#3d1820;color:#ff5d6c;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:700">🔴 Crítico</span>',
            "ALTA":    '<span style="background:#3d3413;color:#f5c451;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:700">🟡 Alto</span>',
            "MEDIA":   '<span style="background:#11294a;color:#4ea1ff;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:700">🔵 Médio</span>',
            "BAIXA":   '<span style="background:#123a26;color:#2fd07a;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:700">🟢 Baixo</span>',
        }

        STATUS_BIZ = {
            "open":         "🔓 Em aberto",
            "investigating": "🔍 Em investigação",
            "resolved":     "✅ Resolvido",
            "closed":       "🔒 Fechado",
        }

        active_incs = [i for i in recent if i.get("status") in ("open", "investigating")][:8]

        if active_incs:
            for inc_item in active_incs:
                alert_data = inc_item.get("alert_data") or {}
                itype = alert_data.get("type") or "other"
                sev = (inc_item.get("severity") or "MEDIA").upper()
                biz_title, biz_what, biz_impact, biz_action = THREAT_BIZ.get(
                    itype, THREAT_BIZ["other"]
                )
                pill = SEV_PILL.get(sev, SEV_PILL["MEDIA"])
                status_txt = STATUS_BIZ.get(inc_item.get("status", "open"), "—")
                inc_id = inc_item.get("incident_id", "—")
                created = (inc_item.get("created_at") or "")[:16]
                expand = sev == "CRITICA"

                with st.expander(
                    f"{biz_title}  ·  {pill}  ·  {status_txt}",
                    expanded=expand,
                ):
                    st.markdown(f"**O que aconteceu?**  \n{biz_what}")
                    st.markdown("---")
                    col_imp, col_act = st.columns(2)
                    with col_imp:
                        st.markdown("**Impacto para o negócio**")
                        st.info(biz_impact)
                    with col_act:
                        st.markdown("**O que está a ser feito**")
                        st.success(biz_action)
                    st.caption(f"Referência interna: `{inc_id}` · Detetado em: {created}")
        else:
            st.success("✅ Não há alertas ativos neste momento.")

        # ---- Ações recomendadas ----
        st.divider()
        st.subheader("📋 Ações Recomendadas")

        actions: List[tuple] = []
        hrs_val = int(avg_risk)

        if open_crit > 0:
            actions.append(("🔴", "Resolver incidente(s) crítico(s)",
                             f"{open_crit} incidente(s) crítico(s) em aberto — contacte a equipa de TI.",
                             "Imediato", "#ff5d6c"))
        if hitl_d.get("pending_count", 0) > 0:
            actions.append(("🟡", "Revisão de alertas pendentes",
                             f"{hitl_d['pending_count']} alerta(s) aguardam validação do analista SOCHAI.",
                             "Hoje", "#f5c451"))
        if trained_pct < 80:
            actions.append(("🟡", "Aumentar cobertura de formação",
                             f"Apenas {trained_pct}% formados. Objetivo: ≥ 80% dos colaboradores.",
                             "Este mês", "#f5c451"))
        if hrs_val >= 60:
            actions.append(("🔴", "Reduzir risco humano (urgente)",
                             f"HRS médio {hrs_val}/100. Lançar simulacro de phishing e formação de reforço.",
                             "Esta semana", "#ff5d6c"))
        elif hrs_val >= 30:
            actions.append(("🟡", "Reforçar formação em cibersegurança",
                             f"HRS médio {hrs_val}/100. Focar nos departamentos com maior risco.",
                             "Este mês", "#f5c451"))
        if global_resilience is not None and global_resilience < 50:
            actions.append(("🟡", "Repetir simulacro de phishing",
                             f"Resiliência atual: {global_resilience:.0f}%. Nova campanha focada nos perfis de maior risco.",
                             "Próximas 2 semanas", "#f5c451"))
        if not actions:
            actions.append(("🟢", "Manter a trajetória positiva",
                             "Situação estável. Continue a monitorizar e a investir na formação.",
                             "Contínuo", "#2fd07a"))

        num_cols = min(len(actions), 3)
        act_cols = st.columns(num_cols)
        for idx, (icon, title, desc, due, hex_c) in enumerate(actions):
            act_cols[idx % num_cols].markdown(f"""
            <div style="border:1px solid {hex_c}44;border-radius:10px;padding:14px 15px;
                        background:{hex_c}0d;margin-bottom:8px">
                <div style="font-size:13px;font-weight:700;margin-bottom:6px">{icon} {title}</div>
                <div style="font-size:12px;color:#8899aa;line-height:1.5;margin-bottom:8px">{desc}</div>
                <div style="font-family:monospace;font-size:11px;color:{hex_c}">⏰ {due}</div>
            </div>
            """, unsafe_allow_html=True)

    elif isinstance(ov, dict) and "error" in ov:
        st.error(f"API offline: {ov['error']}")
        st.code("python api_main.py", language="bash")
    else:
        st.warning("Sem dados analíticos disponíveis.")


# ================================================================== #
# TAB 7 — Cenários de Ataque (simulação guiada para apresentação)
# ================================================================== #
with tabs[6]:
    st.header("🎬 Cenários de Ataque — Simulação Guiada")
    st.caption(
        "Lança um cenário com vários incidentes relacionados e gera automaticamente "
        "os playbooks de resposta e as missões de formação (gamificação) associadas."
    )

    scn_tabs = st.tabs([
        "📚 Cenário do catálogo",
        "🖥️ Cenário a partir dos ativos reais",
    ])

    # ---------------------------------------------------------------- #
    # 7.1 — Cenário narrativo do catálogo
    # ---------------------------------------------------------------- #
    with scn_tabs[0]:
        catalog = api("get", "/api/scenarios")
        if isinstance(catalog, list) and catalog:
            options = {s["id"]: s for s in catalog}
            ui_state.keep_valid("scn_catalog_sel", list(options.keys()))
            sel_id = st.selectbox(
                "Cenário",
                options=list(options.keys()),
                format_func=lambda k: f"{options[k]['name']} ({options[k]['incident_count']} incidentes)",
                key="scn_catalog_sel",
            )
            sel = options[sel_id]
            st.write(sel["description"])
            st.caption("Tipos de ameaça envolvidos: " + ", ".join(sel["threat_types"]))

            run_btn = st.button("🚀 Executar Cenário", use_container_width=True, type="primary")

            if run_btn:
                with st.spinner(
                    "A gerar incidentes, a associar playbooks e a criar cenários de formação... "
                    "(pode demorar até 1 minuto)"
                ):
                    run_result = api(
                        "post", "/api/scenarios/run",
                        json={"scenario_id": sel_id}, timeout=120,
                    )
                if "error" in run_result:
                    st.error(run_result["error"])
                else:
                    st.session_state["last_scenario_result"] = run_result
                    ui_state.mark_fresh("last_scenario_result")

            result = st.session_state.get("last_scenario_result")
            if result and result.get("scenario_id") == sel_id:
                _snap_at = ui_state.from_snapshot("last_scenario_result")
                if _snap_at:
                    st.info(
                        f"📂 Resultado reposto do estado gravado em "
                        f"{_snap_at[:16].replace('T', ' ')} — não foi executado agora. "
                        "Volte a carregar em **Executar Cenário** para gerar incidentes novos."
                    )
                st.success(
                    f"✅ Cenário **{result['scenario_name']}** executado — "
                    f"{len(result['incidents'])} incidente(s) criado(s)."
                )

                st.subheader("🚨 Incidentes Gerados")
                rows = [{
                    "Incidente": inc["incident_id"],
                    "Tipo": inc["type"],
                    "Severidade": inc["severity"],
                    "ML Score": inc["ml_score"],
                    "HITL": "Sim" if inc["hitl_required"] else "Não",
                    "Playbook": inc["playbook_id"],
                    "Ativo Afetado": inc.get("asset_name") or "— (sem correspondência)",
                    "Criticidade": inc.get("asset_criticality") or "—",
                } for inc in result["incidents"]]
                st.dataframe(rows, use_container_width=True, hide_index=True)
                n_com_ativo = sum(1 for inc in result["incidents"] if inc.get("asset_id"))
                st.caption(
                    f"🖥️ {n_com_ativo}/{len(result['incidents'])} incidente(s) associados automaticamente "
                    "a um ativo real (por IP de origem ou IP mencionado na descrição do alerta) — "
                    "ver tab **Ativos** para o inventário completo."
                )

                st.subheader("📋 Playbooks Associados")
                for pb in result["playbooks"]:
                    with st.expander(
                        f"**{pb['name']}** [{pb.get('playbook_id', '—')}] — {pb.get('threat_type', '')}"
                    ):
                        if pb.get("priority_actions"):
                            st.write("**⚡ Ações Prioritárias:**")
                            for pa in pb["priority_actions"]:
                                st.markdown(f"- 🔴 {pa}")
                        st.write("**📋 Passos:**")
                        for step in pb.get("steps", []):
                            st.markdown(f"- {step}")

                st.subheader("🎮 Cenários de Formação Gerados")
                st.caption("Já disponíveis na tab Gamificação → Missões.")
                for sc in result["training_missions"]:
                    with st.expander(
                        f"🎯 **{sc.get('title', '—')}** | {sc.get('difficulty', '—')} "
                        f"| ⭐ {sc.get('xp_reward', 0)} XP"
                    ):
                        st.write(sc.get("description", ""))
                        for qi, q in enumerate(sc.get("questions", [])):
                            st.write(f"**Q{qi + 1}.** {q['question']}")

                if result.get("phishing_campaign"):
                    camp = result["phishing_campaign"]
                    st.subheader("🎣 Campanha de Phishing Sugerida")
                    st.info(
                        f"Campanha **{camp['name']}** lançada para {camp['targets']} colaborador(es) "
                        "— já disponível nas tabs Gamificação e Analytics."
                    )
        else:
            st.error("Não foi possível carregar o catálogo de cenários.")

    # ---------------------------------------------------------------- #
    # 7.2 — Cenário gerado a partir das vulnerabilidades dos ativos reais
    # ---------------------------------------------------------------- #
    with scn_tabs[1]:
        st.subheader("🖥️ Cenário / Incidente a partir dos Ativos do Inventário")
        st.caption(
            "Analisa os ativos que existem na tab **Ativos** (serviços expostos e "
            "configuração de segurança), identifica as vulnerabilidades reais de cada um "
            "e constrói o incidente que a sua exploração produziria. De cada "
            "vulnerabilidade encontrada nasce o **playbook** de resposta e, em "
            "consequência, a **missão de gamificação** e o impacto no risco humano dos "
            "colaboradores donos do ativo afetado."
        )

        scan = api("get", "/api/scenarios/asset-risks", timeout=30)
        if not (isinstance(scan, dict) and "assets" in scan):
            st.error(
                (scan or {}).get("error", "Não foi possível analisar o inventário de ativos.")
            )
        else:
            summary = scan["summary"]
            s1, s2, s3, s4 = st.columns(4)
            s1.markdown(metric_card("Ativos analisados", summary["assets_scanned"]),
                        unsafe_allow_html=True)
            s2.markdown(metric_card("Ativos com falhas", summary["assets_at_risk"], "yellow"),
                        unsafe_allow_html=True)
            s3.markdown(metric_card("Vulnerabilidades", summary["vulnerabilities_found"], "red"),
                        unsafe_allow_html=True)
            s4.markdown(metric_card("Achados críticos", summary["critical_findings"], "red"),
                        unsafe_allow_html=True)

            profiles = [p for p in scan["assets"] if p["vulnerability_count"]]
            if not profiles:
                st.success(
                    "✅ Nenhum ativo do inventário apresenta fragilidades detetáveis — "
                    "não há cenário para gerar. Registe serviços e configuração de "
                    "segurança nos ativos (tab **Ativos**) para alimentar esta análise."
                )
            else:
                st.divider()
                st.write("**🔎 Superfície de ataque detetada no inventário**")
                st.dataframe(
                    [{
                        "Ativo": p["asset_name"],
                        "Tipo": p["asset_type"] or "—",
                        "IP": p["ip_address"] or "—",
                        "Criticidade": p["criticality"],
                        "Risco (0-100)": p["risk_score"],
                        "Vulnerabilidades": p["vulnerability_count"],
                        "Mais grave": p["top_severity"] or "—",
                        "Ameaças possíveis": ", ".join(p["threat_types"]),
                    } for p in profiles],
                    use_container_width=True, hide_index=True,
                )

                crit_icon = {"CRITICO": "🔴", "ALTO": "🟠", "MEDIO": "🟡", "BAIXO": "🟢"}
                with st.expander("📄 Detalhe das vulnerabilidades por ativo"):
                    for p in profiles:
                        st.markdown(
                            f"**{crit_icon.get(p['criticality'], '⚪')} "
                            f"{p['asset_name']}** — risco {p['risk_score']}/100"
                        )
                        for v in p["vulnerabilities"]:
                            st.markdown(
                                f"- {sev_icon(v['severity'])} **{v['title']}** "
                                f"({v['severity']}) — _{v['evidence']}_  \n"
                                f"  ↳ permite: `{v['threat_type']}` · correção: {v['remediation']}"
                            )
                        st.divider()

                st.write("**⚙️ Configuração do cenário**")
                by_id = {p["asset_id"]: p for p in profiles}
                # Pré-seleção: os 3 ativos mais expostos e, se nenhum deles tiver
                # colaborador associado, o ativo com dono mais em risco — sem ele
                # o cenário não chega à camada de gamificação.
                default_assets = [p["asset_id"] for p in profiles[:3]]
                if not any(by_id[i]["linked_users"] for i in default_assets):
                    owned = next((p for p in profiles if p["linked_users"]), None)
                    if owned:
                        default_assets.append(owned["asset_id"])
                # Descarta do snapshot os ativos apagados entretanto, para não
                # ficarem a ser regravados indefinidamente em cada "Guardar estado".
                ui_state.keep_valid("asset_scn_assets", list(by_id.keys()))
                sel_assets = st.multiselect(
                    "Ativos a incluir (vazio = todo o inventário)",
                    options=list(by_id.keys()),
                    default=default_assets,
                    format_func=lambda k: (
                        f"{by_id[k]['asset_name']} — risco {by_id[k]['risk_score']} "
                        f"({by_id[k]['vulnerability_count']} vulnerabilidades)"
                    ),
                    key="asset_scn_assets",
                )
                o1, o2 = st.columns(2)
                max_inc = o1.slider("Nº máximo de incidentes", 1, 10, 4, key="asset_scn_max")
                per_asset = o2.slider(
                    "Máx. vulnerabilidades por ativo", 1, 3, 2, key="asset_scn_per_asset"
                )
                gen_pb = st.checkbox(
                    "Gerar playbooks à medida com IA (RAG + LLM) — mais lento",
                    value=True, key="asset_scn_genpb",
                    help=(
                        "Sem chave de LLM configurada, ou se a geração falhar, o cenário "
                        "usa o playbook curado da biblioteca para o tipo de ameaça."
                    ),
                )
                launch_ph = st.checkbox(
                    "Lançar simulação de phishing quando a falha for do domínio humano",
                    value=True, key="asset_scn_phish",
                )

                gen_scn_btn = st.button(
                    "🧨 Gerar Cenário a partir dos Ativos",
                    use_container_width=True, type="primary", key="asset_scn_run",
                )

                if gen_scn_btn:
                    with st.spinner(
                        "A explorar as vulnerabilidades dos ativos, a gerar os playbooks "
                        "de resposta e as missões de formação... (pode demorar até 2 minutos)"
                    ):
                        asset_result = api(
                            "post", "/api/scenarios/from-assets",
                            json={
                                "asset_ids": sel_assets,
                                "max_incidents": max_inc,
                                "max_per_asset": per_asset,
                                "generate_playbooks": gen_pb,
                                "launch_phishing": launch_ph,
                            },
                            timeout=180,
                        )
                    if "error" in asset_result:
                        st.error(asset_result["error"])
                    else:
                        st.session_state["asset_scenario_result"] = asset_result
                        ui_state.mark_fresh("asset_scenario_result")

                ares = st.session_state.get("asset_scenario_result")
                if ares:
                    st.divider()
                    _ares_snap = ui_state.from_snapshot("asset_scenario_result")
                    if _ares_snap:
                        st.info(
                            f"📂 Resultado reposto do estado gravado em "
                            f"{_ares_snap[:16].replace('T', ' ')} — não foi executado agora."
                        )
                    st.success(
                        f"✅ **{ares['scenario_name']}** — "
                        f"{len(ares['incidents'])} incidente(s), "
                        f"{len(ares['playbooks'])} playbook(s) e "
                        f"{len(ares['training_missions'])} missão(ões) de formação geradas."
                    )
                    st.caption(
                        f"Cenário `{ares['scenario_id']}` · ativos afetados: "
                        + ", ".join(ares["assets_affected"])
                    )
                    if gen_pb and not ares.get("playbooks_generated_by_ai"):
                        motivo = (
                            "a geração com LLM não devolveu resultado"
                            if ares.get("llm_available")
                            else "não há chave de LLM configurada"
                        )
                        st.warning(
                            f"Os playbooks vieram da biblioteca curada — {motivo}. "
                            "A resposta a cada vulnerabilidade mantém-se válida, mas não "
                            "está adaptada ao ativo concreto."
                        )

                    st.subheader("🚨 Incidentes gerados a partir das vulnerabilidades")
                    st.dataframe(
                        [{
                            "Incidente": inc["incident_id"],
                            "Ativo": inc["asset_name"],
                            "Criticidade": inc["asset_criticality"],
                            "Vulnerabilidade explorada": inc["vulnerability"],
                            "Tipo": inc["type"],
                            "Severidade": inc["severity"],
                            "ML Score": inc["ml_score"],
                            "HITL": "Sim" if inc["hitl_required"] else "Não",
                            "Playbook": inc["playbook_id"] or "—",
                        } for inc in ares["incidents"]],
                        use_container_width=True, hide_index=True,
                    )
                    with st.expander("🔬 Narrativa de cada incidente e correção recomendada"):
                        for inc in ares["incidents"]:
                            st.markdown(
                                f"**{sev_icon(inc['severity'])} {inc['incident_id']} — "
                                f"{inc['asset_name']}**"
                            )
                            st.write(inc["description"])
                            st.caption(
                                f"Evidência no inventário: {inc['evidence']} · "
                                f"Correção: {inc['remediation']}"
                            )
                            st.divider()

                    st.subheader("📋 Playbooks gerados para estas vulnerabilidades")
                    for pb in ares["playbooks"]:
                        origem = "🤖 gerado por IA" if pb.get("is_generated") else "📚 biblioteca curada"
                        with st.expander(
                            f"**{pb['name']}** [{pb.get('playbook_id', '—')}] — "
                            f"{pb.get('threat_type', '')} · {origem}"
                        ):
                            st.caption(
                                "Responde a: "
                                + "; ".join(
                                    f"{v['title']} em {v['asset_name']}"
                                    for v in pb.get("vulnerabilities", [])
                                )
                            )
                            if pb.get("priority_actions"):
                                st.write("**⚡ Ações Prioritárias:**")
                                for pa in pb["priority_actions"]:
                                    st.markdown(f"- 🔴 {pa}")
                            st.write("**📋 Passos:**")
                            for step in pb.get("steps", []):
                                st.markdown(f"- {step}")
                            if pb.get("estimated_time"):
                                st.caption(f"⏱️ Tempo estimado: {pb['estimated_time']}")
                            if pb.get("escalation_criteria"):
                                st.caption(f"⬆️ Escalar quando: {pb['escalation_criteria']}")

                    st.subheader("👥 Impacto nos colaboradores (risco humano)")
                    if ares["affected_users"]:
                        st.dataframe(
                            [{
                                "Colaborador": u.get("full_name") or u["username"],
                                "Ativo afetado": u.get("asset_name") or "—",
                                "Vulnerabilidade": u.get("vulnerability") or "—",
                                "Novo Human Risk Score": u["new_risk_score"],
                            } for u in ares["affected_users"]],
                            use_container_width=True, hide_index=True,
                        )
                        st.caption(
                            "O incidente no ativo sobe o risco humano do seu responsável "
                            "e gera-lhe uma missão dirigida — ver tab **Resultados** para "
                            "a evolução do HRS."
                        )
                    else:
                        st.info(
                            "Nenhum dos ativos afetados tem colaborador associado. "
                            "Associe colaboradores aos ativos (tab **Gamificação → "
                            "Utilizadores**) para que os incidentes gerem risco humano "
                            "e missões dirigidas."
                        )

                    st.subheader("🎮 Missões de formação geradas")
                    st.caption(
                        "Já disponíveis na tab **Gamificação → Missões** e no portal do colaborador."
                    )
                    for sc in ares["training_missions"]:
                        alvo = (
                            f" · 🎯 {sc['target_username']}" if sc.get("target_username") else ""
                        )
                        with st.expander(
                            f"🎯 **{sc.get('title', '—')}** | {sc.get('difficulty', '—')} "
                            f"| ⭐ {sc.get('xp_reward', 0)} XP{alvo}"
                        ):
                            if sc.get("vulnerability"):
                                st.caption(f"Origem: {sc['vulnerability']} em {sc.get('asset_name', '—')}")
                            st.write(sc.get("description", ""))
                            for qi, q in enumerate(sc.get("questions", [])):
                                st.write(f"**Q{qi + 1}.** {q['question']}")

                    if ares.get("phishing_campaign"):
                        camp = ares["phishing_campaign"]
                        st.subheader("🎣 Campanha de Phishing Lançada")
                        st.info(
                            f"Campanha **{camp['name']}** lançada para "
                            f"{camp['targets']} colaborador(es) — já disponível nas tabs "
                            "Gamificação e Analytics."
                        )


# ================================================================== #
# TAB 8 — Resultados & Evolução da Gamificação (L5)
# ================================================================== #
with tabs[7]:
    import json as _json
    import subprocess
    import sys
    from pathlib import Path as _Path

    st.header("📈 Resultados & Evolução — Gamificação (L5)")
    st.caption(
        "Resultados calculados em tempo real a partir dos **colaboradores registados** "
        "(HRS, XP, missões, badges e campanhas de phishing). Atualiza sempre que o "
        "separador é aberto ou o botão de atualizar é usado."
    )

    if st.button("🔄 Atualizar resultados", key="res_refresh"):
        st.rerun()

    _live_users = api("get", "/api/users")
    _live_camps = api("get", "/api/phishing/campaigns")

    if not isinstance(_live_users, list) or not _live_users:
        st.warning("Sem colaboradores para analisar (API offline ou sem utilizadores registados).")
    else:
        _staff = [u for u in _live_users if (u.get("role") or "").lower() != "admin"] or _live_users
        _dfu = pd.DataFrame([{
            "Colaborador": u.get("full_name") or u.get("username"),
            "Utilizador": u.get("username"),
            "Departamento": u.get("department") or "—",
            "HRS": float(u.get("risk_score") or 0),
            "XP": int(u.get("xp_points") or 0),
            "Nível": int(u.get("level") or 1),
            "Missões feitas": int(u.get("total_missions") or 0),
            "Missões aprovadas": int(u.get("missions_completed") or 0),
            "Badges": len(u.get("badges") or []),
        } for u in _staff])

        def _hrs_band(v):
            return "Alto (≥50)" if v >= 50 else "Médio (20–50)" if v >= 20 else "Baixo (<20)"

        _dfu["Banda"] = _dfu["HRS"].map(_hrs_band)
        _avg = _dfu["HRS"].mean()

        st.divider()
        st.subheader("1 · Visão geral dos colaboradores")
        _kc = st.columns(5)
        _kc[0].markdown(metric_card("Colaboradores", len(_dfu)), unsafe_allow_html=True)
        _kc[1].markdown(metric_card(
            "HRS médio", f"{_avg:.1f}",
            "red" if _avg >= 50 else "yellow" if _avg >= 20 else "green",
        ), unsafe_allow_html=True)
        _kc[2].markdown(metric_card("HRS ≥ 50", int((_dfu["HRS"] >= 50).sum()), "red"), unsafe_allow_html=True)
        _kc[3].markdown(metric_card("XP total", int(_dfu["XP"].sum())), unsafe_allow_html=True)
        _kc[4].markdown(metric_card(
            "Com formação", f"{int((_dfu['Missões aprovadas'] > 0).sum())}/{len(_dfu)}"
        ), unsafe_allow_html=True)

        _order = _dfu.sort_values("HRS", ascending=False)["Colaborador"].tolist()
        st.altair_chart(
            alt.Chart(_dfu).mark_bar().encode(
                y=alt.Y("Colaborador:N", sort=_order, title=None),
                x=alt.X("HRS:Q", scale=alt.Scale(domain=[0, 100]), title="Human Risk Score"),
                color=alt.Color("Banda:N", scale=alt.Scale(
                    domain=["Baixo (<20)", "Médio (20–50)", "Alto (≥50)"],
                    range=["#2fd07a", "#f5c451", "#ff5d6c"],
                ), legend=alt.Legend(orient="top")),
                tooltip=["Colaborador", "Departamento", "HRS", "XP", "Nível"],
            ),
            use_container_width=True,
        )
        st.dataframe(
            _dfu.drop(columns=["Utilizador", "Banda"]).sort_values("HRS", ascending=False),
            use_container_width=True, hide_index=True,
        )

        st.divider()
        st.subheader("2 · Desempenho por nível e competência")
        st.caption(
            "Cada nível reflete a competência acumulada (XP). Compara o HRS médio, "
            "a taxa de aprovação em missões e o número de colaboradores em cada nível."
        )
        _den_lv = _dfu["Missões feitas"].astype(float)
        _dfu["Taxa aprovação (%)"] = (
            _dfu["Missões aprovadas"].astype(float) / _den_lv.where(_den_lv > 0) * 100
        ).round(0)
        _dlv = _dfu.groupby("Nível").agg(
            Colaboradores=("Colaborador", "count"),
            HRS_médio=("HRS", "mean"),
            XP_médio=("XP", "mean"),
            **{"Taxa aprovação (%)": ("Taxa aprovação (%)", "mean")},
        ).reset_index().round(1).sort_values("Nível")
        _lv1, _lv2 = st.columns(2)
        with _lv1:
            st.altair_chart(
                alt.Chart(_dlv).mark_bar().encode(
                    x=alt.X("Nível:O", title="Nível"),
                    y=alt.Y("HRS_médio:Q", scale=alt.Scale(domain=[0, 100]), title="HRS médio"),
                    tooltip=["Nível", "Colaboradores", "HRS_médio"],
                ),
                use_container_width=True,
            )
        with _lv2:
            st.altair_chart(
                alt.Chart(_dlv).mark_bar(color="#3aa0ff").encode(
                    x=alt.X("Nível:O", title="Nível"),
                    y=alt.Y("Taxa aprovação (%):Q", scale=alt.Scale(domain=[0, 100])),
                    tooltip=["Nível", "Colaboradores", "Taxa aprovação (%)"],
                ),
                use_container_width=True,
            )
        st.dataframe(_dlv, use_container_width=True, hide_index=True)

        st.divider()
        st.subheader("2b · Evolução do Risk Score dos colaboradores")
        _hist = api("get", "/api/gamification/history")
        if isinstance(_hist, list) and _hist:
            _dh = pd.DataFrame(_hist)
            _dh["created_at"] = pd.to_datetime(_dh["created_at"], errors="coerce")
            _names_h = dict(zip(_dfu["Utilizador"], _dfu["Colaborador"]))
            _dh["Colaborador"] = _dh["username"].map(_names_h).fillna(_dh["username"])
            _dh = _dh.sort_values(["user_id", "created_at"])
            _dh["Passo"] = _dh.groupby("user_id").cumcount() + 1
            _EV = {"mission": "Missão", "phishing_sim": "Simulação phishing", "phishing_report": "Reporte phishing"}
            _dh["Evento"] = _dh["event_type"].map(_EV).fillna(_dh["event_type"])

            _people = sorted(_dh["Colaborador"].unique().tolist())
            _sel = st.multiselect(
                "Colaboradores a mostrar", _people, default=_people[: min(6, len(_people))],
            )
            _dhs = _dh[_dh["Colaborador"].isin(_sel)] if _sel else _dh

            _rule_h = alt.Chart(pd.DataFrame({"y": [20, 50]})).mark_rule(
                strokeDash=[4, 4], color="#8899aa"
            ).encode(y="y:Q")
            _line_h = alt.Chart(_dhs).mark_line(point=True).encode(
                x=alt.X("Passo:O", title="Evento (ordem cronológica)"),
                y=alt.Y("risk_score:Q", scale=alt.Scale(domain=[0, 100]), title="Human Risk Score"),
                color=alt.Color("Colaborador:N", legend=alt.Legend(orient="top")),
                tooltip=["Colaborador", "Passo", "Evento", "detail", "risk_score", "risk_delta"],
            )
            st.altair_chart(_rule_h + _line_h, use_container_width=True)

            st.dataframe(
                _dh[["Colaborador", "Evento", "detail", "difficulty", "risk_score", "risk_delta", "created_at"]]
                .rename(columns={"detail": "Detalhe", "difficulty": "Dificuldade",
                                  "risk_score": "HRS", "risk_delta": "Δ HRS", "created_at": "Data/Hora"})
                .sort_values("Data/Hora", ascending=False),
                use_container_width=True, hide_index=True,
            )
        else:
            st.info(
                "Ainda não há histórico de eventos de risco. O histórico começa a partir de agora "
                "— missões, simulações de phishing e reportes futuros vão aparecer aqui."
            )

        st.divider()
        st.subheader("3 · Risco e formação por departamento")
        _dd = _dfu.groupby("Departamento").agg(
            Colaboradores=("Colaborador", "count"),
            HRS_médio=("HRS", "mean"),
            XP_médio=("XP", "mean"),
            Missões_aprovadas=("Missões aprovadas", "sum"),
        ).reset_index().round(1)
        st.altair_chart(
            alt.Chart(_dd).mark_bar().encode(
                x=alt.X("Departamento:N", title=None),
                y=alt.Y("HRS_médio:Q", scale=alt.Scale(domain=[0, 100]), title="HRS médio"),
                tooltip=["Departamento", "Colaboradores", "HRS_médio", "XP_médio", "Missões_aprovadas"],
            ),
            use_container_width=True,
        )

        st.divider()
        st.subheader("4 · Campanhas de phishing — resultado por colaborador")
        _rows_ph = []
        if isinstance(_live_camps, list):
            for _c in _live_camps:
                _det = api("get", f"/api/phishing/campaigns/{_c['campaign_id']}")
                for _t in (_det.get("targets") or []) if isinstance(_det, dict) else []:
                    _rows_ph.append({
                        "Campanha": _c["name"],
                        "Utilizador": _t["username"],
                        "Desfecho": _t["outcome"],
                        "Tempo (s)": _t.get("time_to_action_seconds"),
                    })
        if _rows_ph:
            _dph = pd.DataFrame(_rows_ph)
            _names = dict(zip(_dfu["Utilizador"], _dfu["Colaborador"]))
            _dph["Colaborador"] = _dph["Utilizador"].map(_names).fillna(_dph["Utilizador"])
            _pv = _dph.pivot_table(
                index="Colaborador", columns="Desfecho", values="Campanha",
                aggfunc="count", fill_value=0,
            ).reset_index()
            for _o in ("reported", "ignored", "clicked"):
                if _o not in _pv:
                    _pv[_o] = 0
            _den_pv = (_pv["reported"] + _pv["clicked"]).astype(float)
            _pv["Resiliência (%)"] = (
                _pv["reported"].astype(float) / _den_pv.where(_den_pv > 0) * 100
            ).round(0)
            st.dataframe(
                _pv.rename(columns={"reported": "Reportou", "ignored": "Ignorou", "clicked": "Clicou"}),
                use_container_width=True, hide_index=True,
            )
            _tc = _dph["Desfecho"].value_counts()
            _den = _tc.get("reported", 0) + _tc.get("clicked", 0)
            _oc = st.columns(3)
            _oc[0].markdown(metric_card("Cliques", int(_tc.get("clicked", 0)), "red"), unsafe_allow_html=True)
            _oc[1].markdown(metric_card("Reportes", int(_tc.get("reported", 0)), "green"), unsafe_allow_html=True)
            _oc[2].markdown(metric_card(
                "Resiliência global",
                f"{_tc.get('reported', 0) / _den * 100:.0f}%" if _den else "—",
            ), unsafe_allow_html=True)
        else:
            st.info("Ainda não há campanhas de phishing com alvos. Lance uma no separador Gamificação.")

    st.divider()
    if not st.toggle("🧪 Mostrar simulações sintéticas de referência (n=15, seed=42)", key="res_show_sim"):
        st.stop()

    st.subheader("Simulações sintéticas de referência")
    st.caption(
        "Duas simulações reprodutíveis sobre o motor real (GamificationEngine): "
        "**percurso individual** (`simulacao_treino.py`) e **amostra populacional** "
        "(`simulacao_populacional.py`). Não dependem dos colaboradores reais."
    )

    _BASE = _Path(__file__).resolve().parent
    _F_TREINO = _BASE / "simulacao_treino_resultados.json"
    _F_POP = _BASE / "simulacao_populacional_resultados.json"

    def _load_json(path):
        try:
            with open(path, encoding="utf-8") as fh:
                return _json.load(fh)
        except FileNotFoundError:
            return None
        except Exception as exc:  # noqa: BLE001
            return {"__error__": str(exc)}

    _cr, _cinfo = st.columns([1, 2])
    with _cr:
        if st.button("▶️ Correr / atualizar simulações", use_container_width=True):
            _out, _all_ok = [], True
            with st.spinner("A correr as simulações sobre o GamificationEngine..."):
                for _script in ("simulacao_treino.py", "simulacao_populacional.py"):
                    _proc = subprocess.run(
                        [sys.executable, str(_BASE / _script)],
                        cwd=str(_BASE), capture_output=True, text=True,
                    )
                    _all_ok = _all_ok and _proc.returncode == 0
                    _out.append(f"$ python {_script}\n{_proc.stdout}{_proc.stderr}")
            st.session_state["_sim_logs"] = "\n\n".join(_out)
            ui_state.mark_fresh("_sim_logs")
            if _all_ok:
                st.success("Simulações concluídas — resultados atualizados.")
            else:
                st.error("Falha ao correr uma das simulações — ver logs abaixo.")

    _treino = _load_json(_F_TREINO)
    _pop = _load_json(_F_POP)

    with _cinfo:
        _stamps = []
        if isinstance(_treino, dict) and _treino.get("gerado_em"):
            _stamps.append(f"individual {_treino['gerado_em'][:19]}")
        if isinstance(_pop, dict) and _pop.get("gerado_em"):
            _stamps.append(f"populacional {_pop['gerado_em'][:19]}")
        if _stamps:
            st.caption("🕒 Resultados gerados em: " + " · ".join(_stamps))

    if st.session_state.get("_sim_logs"):
        _logs_snap = ui_state.from_snapshot("_sim_logs")
        _logs_label = (
            f"🖥️ Logs das simulações — do estado gravado em {_logs_snap[:16].replace('T', ' ')}"
            if _logs_snap else "🖥️ Logs da última execução das simulações"
        )
        with st.expander(_logs_label):
            st.code(st.session_state["_sim_logs"])

    for _d in (_treino, _pop):
        if isinstance(_d, dict) and _d.get("__error__"):
            st.error(f"Erro a ler resultados: {_d['__error__']}")

    _has_treino = isinstance(_treino, dict) and "jornada" in _treino
    _has_pop = isinstance(_pop, dict) and "populacao" in _pop

    if not _has_treino and not _has_pop:
        st.warning(
            "Ainda não há ficheiros de resultados. Clique em "
            "**▶️ Correr / atualizar simulações** ou execute na linha de comandos:\n\n"
            "```\npython simulacao_treino.py\npython simulacao_populacional.py\n```"
        )
        st.stop()

    _RISK_SCALE = alt.Scale(domain=[0, 70])
    _GRP = {"alto": "Competência alta", "medio": "Competência média", "baixo": "Competência baixa"}
    _GRP_ORDER = ["Competência alta", "Competência média", "Competência baixa"]

    # ---------------------------------------------------------------- #
    # 1 · Evolução do HRS — percurso individual
    # ---------------------------------------------------------------- #
    if _has_treino:
        st.divider()
        st.subheader("1 · Evolução do Human Risk Score — percurso individual")
        st.caption(
            "Um colaborador percorre 5 missões base, 2 simulações de phishing e "
            "sofre 1 incidente de segurança real. Compara o algoritmo **novo** "
            "(history-aware) com o **antigo** (recalculava sempre a partir de base fixa)."
        )

        _jr = _treino["jornada"]
        _rows = []
        for _i, _s in enumerate(_jr, start=1):
            _rows.append({"n": _i, "Algoritmo": "Novo (history-aware)",
                          "HRS": _s["risk_score_novo"]})
            if _s.get("risk_score_antigo") is not None:
                _rows.append({"n": _i, "Algoritmo": "Antigo (base fixa)",
                              "HRS": _s["risk_score_antigo"]})
        _dfj = pd.DataFrame(_rows)

        _rule = alt.Chart(pd.DataFrame({"y": [20, 50]})).mark_rule(
            strokeDash=[4, 4], color="#8899aa"
        ).encode(y="y:Q")
        _line = alt.Chart(_dfj).mark_line(point=True).encode(
            x=alt.X("n:O", title="Passo da jornada (ver tabela abaixo)"),
            y=alt.Y("HRS:Q", scale=_RISK_SCALE, title="Human Risk Score"),
            color=alt.Color("Algoritmo:N", legend=alt.Legend(orient="top")),
            tooltip=["n", "Algoritmo", "HRS"],
        )
        st.altair_chart(_rule + _line, use_container_width=True)

        st.dataframe([{
            "Passo": _i,
            "Etapa": _s["step"],
            "Tipo": _s["type"],
            "Score": f"{_s['score_percentage']:.0f}%" if _s.get("score_percentage") is not None else "—",
            "XP": _s["xp_earned"],
            "HRS (novo)": _s["risk_score_novo"],
            "Badges": ", ".join(_s.get("badges") or []) or "—",
        } for _i, _s in enumerate(_jr, start=1)], use_container_width=True, hide_index=True)

        _rf = _treino.get("resultado_final_novo", {})
        _tst = _treino.get("testes", {})
        _hrs_f = _rf.get("risk_score", 0)
        _k = st.columns(4)
        _k[0].markdown(metric_card("HRS inicial", "50.0"), unsafe_allow_html=True)
        _k[1].markdown(metric_card(
            f"HRS final ({_rf.get('risk_band', '—')})", f"{_hrs_f:.1f}",
            "red" if _hrs_f >= 50 else "yellow" if _hrs_f >= 20 else "green",
        ), unsafe_allow_html=True)
        _k[2].markdown(metric_card(
            "Nível · XP", f"{_rf.get('nivel', '—')} · {_rf.get('xp_points', '—')}"
        ), unsafe_allow_html=True)
        _passed = _tst.get("passaram", 0)
        _total_t = _passed + _tst.get("falharam", 0)
        _k[3].markdown(metric_card(
            "Testes update_risk_score", f"{_passed}/{_total_t}",
            "green" if _total_t and _passed == _total_t else "red",
        ), unsafe_allow_html=True)
        st.caption(
            "⚠️ O HRS final sobe no último passo porque a jornada termina com um "
            "**incidente de segurança real** imputado ao colaborador (+20), que anula "
            "parte do ganho da formação — comportamento pretendido."
        )

    # ---------------------------------------------------------------- #
    # 2 · Antes / depois — amostra populacional
    # ---------------------------------------------------------------- #
    if _has_pop:
        _p = _pop["populacao"]

        st.divider()
        st.subheader("2 · Antes / depois — HRS médio por estágio (n=15, seed=42)")
        st.caption(
            "15 colaboradores sintéticos em 3 níveis de competência (prob. de acerto "
            "90% / 60% / 30%). HRS médio no início (baseline=50), após as 5 missões "
            "e após uma campanha de phishing simulado."
        )
        _stg = _p["avg_risk_by_stage"]
        _SLAB = {"baseline": "Baseline", "pos_treino": "Pós-treino", "pos_phishing": "Pós-phishing"}
        _SORDER = ["Baseline", "Pós-treino", "Pós-phishing"]
        _dfs = pd.DataFrame([
            {"Estágio": _SLAB[_k], "Grupo": _GRP[_g], "HRS": _v}
            for _g, _dd in _stg.items() for _k, _v in _dd.items()
        ])
        st.altair_chart(alt.Chart(_dfs).mark_bar().encode(
            x=alt.X("Estágio:N", sort=_SORDER, title=None),
            xOffset=alt.XOffset("Grupo:N", sort=_GRP_ORDER),
            y=alt.Y("HRS:Q", scale=alt.Scale(domain=[0, 60]), title="HRS médio"),
            color=alt.Color("Grupo:N", sort=_GRP_ORDER, legend=alt.Legend(orient="top")),
            tooltip=["Grupo", "Estágio", "HRS"],
        ), use_container_width=True)

        _dcols = st.columns(3)
        for _idx, (_g, _lab) in enumerate(_GRP.items()):
            _b, _f = _stg[_g]["baseline"], _stg[_g]["pos_phishing"]
            _dcols[_idx].metric(
                _lab, f"HRS {_f:.1f}", delta=f"{_f - _b:+.1f} vs baseline",
                delta_color="inverse",
            )

        # 3 · Score por cenário
        st.divider()
        st.subheader("3 · Desempenho por cenário e nível de competência")
        _dfsc = pd.DataFrame([
            {"Cenário": _sid, "Grupo": _GRP[_g], "Score médio (%)": _val}
            for _g, _dd in _p["avg_score_by_scenario"].items() for _sid, _val in _dd.items()
        ])
        st.altair_chart(alt.Chart(_dfsc).mark_bar().encode(
            x=alt.X("Cenário:N", title=None),
            xOffset=alt.XOffset("Grupo:N", sort=_GRP_ORDER),
            y=alt.Y("Score médio (%):Q", scale=alt.Scale(domain=[0, 100])),
            color=alt.Color("Grupo:N", sort=_GRP_ORDER, legend=alt.Legend(orient="top")),
            tooltip=["Cenário", "Grupo", "Score médio (%)"],
        ), use_container_width=True)

        # 4 · Campanha de phishing
        st.divider()
        st.subheader("4 · Campanha de phishing simulado — comportamento e resiliência")
        _cs = _p["campaign_stats"]
        _OUT = {"reported": "Reportou", "ignored": "Ignorou", "clicked": "Clicou na isca"}
        _dfc = pd.DataFrame([
            {"Grupo": _GRP[_g], "Desfecho": _OUT[_o], "Colaboradores": _cs[_g][_o]}
            for _g in _cs for _o in ("reported", "ignored", "clicked")
        ])
        _cc1, _cc2 = st.columns([1.4, 1])
        with _cc1:
            st.altair_chart(alt.Chart(_dfc).mark_bar().encode(
                x=alt.X("Grupo:N", sort=_GRP_ORDER, title=None),
                y=alt.Y("Colaboradores:Q"),
                color=alt.Color("Desfecho:N", scale=alt.Scale(
                    domain=["Reportou", "Ignorou", "Clicou na isca"],
                    range=["#2fd07a", "#f5c451", "#ff5d6c"],
                ), legend=alt.Legend(orient="top")),
                tooltip=["Grupo", "Desfecho", "Colaboradores"],
            ), use_container_width=True)
        with _cc2:
            st.altair_chart(alt.Chart(pd.DataFrame([
                {"Grupo": _GRP[_g], "Resiliência (%)": _cs[_g]["resilience_pct"]} for _g in _cs
            ])).mark_bar().encode(
                x=alt.X("Resiliência (%):Q", scale=alt.Scale(domain=[0, 100])),
                y=alt.Y("Grupo:N", sort=_GRP_ORDER, title=None),
                color=alt.Color("Grupo:N", sort=_GRP_ORDER, legend=None),
                tooltip=["Grupo", "Resiliência (%)"],
            ), use_container_width=True)

        _ov = _p.get("campaign_overview", {})
        _res = _ov.get("resilience_pct", 0)
        _o = st.columns(4)
        _o[0].markdown(metric_card("Taxa de cliques", f"{_ov.get('click_rate_pct', 0):.0f}%", "red"), unsafe_allow_html=True)
        _o[1].markdown(metric_card("Taxa de reporte", f"{_ov.get('report_rate_pct', 0):.0f}%", "green"), unsafe_allow_html=True)
        _o[2].markdown(metric_card(
            "Resilience rate global", f"{_res:.0f}%",
            "green" if _res >= 70 else "yellow" if _res >= 40 else "red",
        ), unsafe_allow_html=True)
        _o[3].markdown(metric_card("Tempo médio até ação", f"{_ov.get('avg_time_seconds', 0):.0f}s"), unsafe_allow_html=True)

        # 5 · Percurso individual detalhado
        _ind = _pop.get("individual")
        if _ind:
            st.divider()
            st.subheader("5 · Percurso individual detalhado — mecânica de pontuação")
            st.caption(
                f"Utilizador '{_ind['utilizador']}' com respostas propositadamente "
                "variadas (perfeitas, parciais e totalmente erradas) para expor a "
                "relação score → XP → aprovação."
            )
            st.dataframe([{
                "Cenário": _r["cenario"],
                "Dificuldade": _r["dificuldade"],
                "Acertos": _r["acertos"],
                "Score": f"{_r['score_pct']:.1f}%",
                "XP": _r["xp_ganho"],
                "Aprovado": "✅" if _r["aprovado"] else "❌",
            } for _r in _ind["rows"]], use_container_width=True, hide_index=True)
            _ic = st.columns(4)
            _ic[0].markdown(metric_card("XP total · Nível", f"{_ind['xp_total']} · {_ind['nivel']}"), unsafe_allow_html=True)
            _ic[1].markdown(metric_card("Missões aprovadas", f"{_ind['missions_aprovadas']}/{_ind['missions_total']}"), unsafe_allow_html=True)
            _ic[2].markdown(metric_card("HRS inicial → final", f"{_ind['risk_inicial']:.0f} → {_ind['risk_final']:.1f}"), unsafe_allow_html=True)
            _ic[3].markdown(metric_card(
                "Variação do HRS", f"{_ind['risk_delta_pct']:+.1f}%",
                "green" if _ind["risk_delta_pct"] < 0 else "red",
            ), unsafe_allow_html=True)

    # ---------------------------------------------------------------- #
    # 6 · Contribuição metodológica — correção de update_risk_score()
    # ---------------------------------------------------------------- #
    st.divider()
    st.subheader("6 · Contribuição metodológica — correção do cálculo do HRS")
    st.markdown(
        "O algoritmo original de `update_risk_score()` **recalculava o risco a partir "
        "de uma base fixa (50)** a cada submissão, ignorando o `current_score` "
        "acumulado. Dois colaboradores com históricos opostos, ao obterem o mesmo "
        "resultado numa missão, ficavam com **exatamente o mesmo HRS** — o histórico "
        "era apagado.\n\n"
        "A versão corrigida mistura o histórico com o novo alvo "
        "(`HRS = current·0.7 + alvo·0.3`), preservando a trajetória de cada pessoa."
    )
    st.table([
        {"Colaborador": "A — histórico de risco alto", "HRS atual": 80,
         "Resultado da missão": "90%", "HRS (algoritmo antigo)": 24.0, "HRS (algoritmo novo)": 63.2},
        {"Colaborador": "B — histórico de risco baixo", "HRS atual": 15,
         "Resultado da missão": "90%", "HRS (algoritmo antigo)": 24.0, "HRS (algoritmo novo)": 17.7},
    ])
    if isinstance(_treino, dict) and _treino.get("testes"):
        _t = _treino["testes"]
        if _t.get("falharam", 1) == 0:
            st.success(
                f"✅ {_t['passaram']}/{_t['passaram']} testes de `simulacao_treino.py` "
                "passam — bug confirmado e corrigido."
            )
        else:
            st.error(f"{_t['falharam']} teste(s) a falhar.")


