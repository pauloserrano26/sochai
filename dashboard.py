"""
SOCHAI Dashboard — Streamlit
7 tabs: Ativos | SOCHAI Operations | Playbooks | XAI/HITL | Gamificação | Analytics | Cenários
"""

import math
from datetime import datetime
from typing import Dict, List, Optional

import requests
import streamlit as st

API_BASE = "http://localhost:8000"

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

def api(method: str, path: str, **kwargs):
    timeout = kwargs.pop("timeout", 10)
    try:
        resp = getattr(requests, method)(f"{API_BASE}{path}", timeout=timeout, **kwargs)
        if resp.status_code < 300:
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


def api_online() -> bool:
    r = api("get", "/health")
    return isinstance(r, dict) and r.get("status") == "online"


# ------------------------------------------------------------------ #
# Sidebar
# ------------------------------------------------------------------ #

with st.sidebar:
    st.markdown("# 🛡️ MESI SOCHAI")
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


# ------------------------------------------------------------------ #
# Tabs
# ------------------------------------------------------------------ #

tabs = st.tabs([
    "🖥️ Ativos",
    "🚨 SOCHAI Operations",
    "📋 Playbooks",
    "🔬 XAI / HITL",
    "🎮 Gamificação",
    "📊 Analytics",
    "🎬 Cenários",
])


# ================================================================== #
# TAB 2 — SOCHAI Operations
# ================================================================== #
with tabs[1]:
    st.header("🚨 SOCHAI Operations — Pipeline L1→L6")

    col_form, col_list = st.columns([1, 1.4], gap="large")

    with col_form:
        st.subheader("Submeter Alerta")
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
                    st.write(f"**Ação Recomendada:** {result.get('recommended_action', '—')}")
                    st.write(f"**Ações SOAR Executadas:** {result.get('soar_actions_executed', 0)}")

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

    act_tabs = st.tabs(["📋 Lista de Ativos", "➕ Adicionar Ativo"])

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
                    if a.get("description"):
                        st.caption(a["description"])
                    if a.get("tags"):
                        st.write(" ".join(f"`{t}`" for t in a["tags"]))
                    if st.button("🗑️ Remover Ativo", key=f"del_{a['id']}"):
                        api("delete", f"/api/assets/{a['id']}")
                        st.rerun()
        elif isinstance(assets, dict) and "error" in assets:
            st.error(assets["error"])
        else:
            st.info("Nenhum ativo encontrado. Adicione o primeiro ativo.")

    with act_tabs[1]:
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

    gam_tabs = st.tabs(["🎯 Missões", "🏆 Leaderboard", "👤 Utilizadores", "🤖 Gerar Cenário"])

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
                    st.progress(int(risk), text=f"Human Risk Score: {risk:.1f}/100")
                    badges = u.get("badges", [])
                    if badges:
                        st.write("Badges: " + " ".join(f"`{b}`" for b in badges))

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
            create_btn = st.form_submit_button("Criar Utilizador", use_container_width=True)

        if create_btn:
            if not u_username.strip():
                st.error("O username é obrigatório.")
            else:
                res = api("post", "/api/users", json={
                    "username": u_username, "full_name": u_name,
                    "email": u_email, "role": u_role, "department": u_dept,
                })
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

    catalog = api("get", "/api/scenarios")
    if isinstance(catalog, list) and catalog:
        options = {s["id"]: s for s in catalog}
        sel_id = st.selectbox(
            "Cenário",
            options=list(options.keys()),
            format_func=lambda k: f"{options[k]['name']} ({options[k]['incident_count']} incidentes)",
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

        result = st.session_state.get("last_scenario_result")
        if result and result.get("scenario_id") == sel_id:
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
            } for inc in result["incidents"]]
            st.dataframe(rows, use_container_width=True, hide_index=True)

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


