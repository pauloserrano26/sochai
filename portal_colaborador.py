"""
Portal do Colaborador — vista restrita do SOCHAI.

Acessível a utilizadores com role "colaborador". Expõe apenas:
  - 🎮 Gamificação (missões, leaderboard, reportar email suspeito)
  - 📋 Playbooks (biblioteca, só leitura)
  - 🚨 Incidentes (em curso / por resolver / resolvidos — só leitura)

Chamado a partir de dashboard.py depois do login.
"""

from __future__ import annotations

from typing import Optional

import requests
import streamlit as st

API_BASE = "http://localhost:8000"

_EM_CURSO = ("open", "investigating")
_RESOLVIDOS = ("resolved", "closed")


def _api(method: str, path: str, **kwargs):
    timeout = kwargs.pop("timeout", 10)
    try:
        resp = getattr(requests, method)(f"{API_BASE}{path}", timeout=timeout, **kwargs)
        if resp.status_code < 300:
            return resp.json()
        return {"error": resp.text}
    except requests.exceptions.ConnectionError:
        return {"error": "API offline — inicie: python api_main.py"}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def _sev_icon(s: str) -> str:
    return {"CRITICA": "🔴", "ALTA": "🟠", "MEDIA": "🟡", "BAIXA": "🟢"}.get((s or "").upper(), "⚪")


def _status_label(s: str) -> str:
    return {
        "open": "🔵 Aberto",
        "investigating": "🟡 Em Investigação",
        "resolved": "🟢 Resolvido",
        "closed": "⚫ Fechado",
    }.get(s, s or "—")


# ------------------------------------------------------------------ #
# Incidentes (só leitura)
# ------------------------------------------------------------------ #

def _render_incident(inc: dict) -> None:
    sev = inc.get("severity", "MEDIA")
    with st.expander(
        f"{_sev_icon(sev)} [{inc.get('incident_id', '—')}] {inc.get('title', '—')} "
        f"— {_status_label(inc.get('status', ''))}"
    ):
        c1, c2, c3 = st.columns(3)
        c1.metric("Severidade", (sev or "—").title())
        c2.metric("ML Score", f"{(inc.get('ml_score') or 0):.2f}")
        c3.metric("Playbook", inc.get("playbook_id") or "—")
        st.caption(f"Criado: {(inc.get('created_at') or '')[:16]}")
        if inc.get("resolved_at"):
            st.caption(f"Resolvido: {(inc.get('resolved_at') or '')[:16]}")
        if inc.get("asset_name"):
            st.write(
                f"**🖥️ Ativo afetado:** {inc['asset_name']} "
                f"({inc.get('asset_criticality') or '—'})"
            )
        if inc.get("description"):
            st.write(inc["description"])


def _tab_incidentes() -> None:
    st.subheader("🚨 Incidentes")
    st.caption("Vista de acompanhamento — só leitura. A gestão dos incidentes é feita pela equipa SOC.")

    incidents = _api("get", "/api/incidents", params={"limit": 200})
    if isinstance(incidents, dict) and "error" in incidents:
        st.error(incidents["error"])
        return
    if not isinstance(incidents, list):
        incidents = []

    em_curso = [i for i in incidents if i.get("status") in _EM_CURSO]
    por_resolver = [i for i in incidents if i.get("status") == "open"]
    resolvidos = [i for i in incidents if i.get("status") in _RESOLVIDOS]

    c1, c2, c3 = st.columns(3)
    c1.metric("🔴 Em curso", len(em_curso))
    c2.metric("🟠 Por resolver", len(por_resolver))
    c3.metric("🟢 Resolvidos", len(resolvidos))
    st.divider()

    sec = st.radio(
        "Ver",
        ["Em curso", "Por resolver", "Resolvidos", "Todos"],
        horizontal=True,
        key="colab_inc_sec",
    )
    grupos = {
        "Em curso": em_curso,
        "Por resolver": por_resolver,
        "Resolvidos": resolvidos,
        "Todos": incidents,
    }
    alvo = grupos[sec]
    if not alvo:
        st.info("Sem incidentes nesta categoria.")
        return
    for inc in alvo:
        _render_incident(inc)


# ------------------------------------------------------------------ #
# Playbooks (só leitura)
# ------------------------------------------------------------------ #

def _tab_playbooks() -> None:
    st.subheader("📋 Playbooks de Resposta a Incidentes")
    st.caption("Procedimentos de referência. Consulta apenas.")

    library = _api("get", "/api/playbooks/library")
    db_pbs = _api("get", "/api/playbooks")

    pbs = []
    seen = set()
    if isinstance(library, list):
        for pb in library:
            pbs.append({
                "name": pb.get("name", "—"),
                "ref": pb.get("id", "—"),
                "threat": (pb.get("threat_type") or "").title(),
                "sev": "",
                "priority_actions": pb.get("priority_actions", []),
                "steps": pb.get("steps", []),
                "tags": pb.get("tags", []),
            })
            seen.add(pb.get("name"))
    if isinstance(db_pbs, list):
        for pb in db_pbs:
            if pb.get("name") in seen:
                continue
            pbs.append({
                "name": pb.get("name", "—"),
                "ref": pb.get("playbook_id", "—"),
                "threat": (pb.get("threat_type") or "").title(),
                "sev": pb.get("severity_level", ""),
                "priority_actions": pb.get("priority_actions", []),
                "steps": pb.get("steps", []),
                "tags": pb.get("tags", []),
            })

    if isinstance(library, dict) and "error" in library and not pbs:
        st.error(library["error"])
        return
    if not pbs:
        st.info("Nenhum playbook disponível.")
        return

    query = st.text_input("🔎 Filtrar por nome / tipo / tag", key="colab_pb_q").strip().lower()
    for pb in pbs:
        haystack = " ".join([
            pb["name"], pb["threat"], pb["sev"], " ".join(pb["tags"])
        ]).lower()
        if query and query not in haystack:
            continue
        title = f"**{pb['name']}** [{pb['ref']}]"
        if pb["threat"]:
            title += f" — {pb['threat']}"
        if pb["sev"]:
            title += f" | {pb['sev']}"
        with st.expander(title):
            if pb["priority_actions"]:
                st.write("**⚡ Ações prioritárias:**")
                for pa in pb["priority_actions"]:
                    st.markdown(f"- 🔴 {pa}")
            if pb["steps"]:
                st.write("**📋 Passos:**")
                for step in pb["steps"]:
                    st.markdown(f"- {step}")
            if pb["tags"]:
                st.write("Tags: " + " ".join(f"`{t}`" for t in pb["tags"]))


# ------------------------------------------------------------------ #
# Gamificação
# ------------------------------------------------------------------ #

def _own_user_id(profile_user_id: Optional[int], key: str) -> Optional[int]:
    """
    Devolve o user_id a usar nas ações de gamificação. Uma conta associada
    (caso normal) usa sempre o seu próprio perfil — sem escolha. Só a conta
    de demonstração (sem perfil associado) mostra um campo manual, para não
    ficar completamente inutilizável.
    """
    if profile_user_id is not None:
        return profile_user_id
    st.caption(
        "⚠️ Esta conta não está associada a um perfil — modo de demonstração. "
        "Pede a um administrador para te associar a um utilizador."
    )
    return st.number_input("ID do utilizador (demo)", min_value=1, key=f"{key}_num")


def _gam_missoes(profile_user_id: Optional[int]) -> None:
    diff_f = st.selectbox(
        "Dificuldade", ["Todas", "INICIANTE", "INTERMEDIO", "AVANCADO"], key="colab_diff_filter"
    )
    scenarios = _api(
        "get", "/api/gamification/scenarios",
        params={"difficulty": diff_f if diff_f != "Todas" else None},
    )
    diff_icons = {"INICIANTE": "🟢", "INTERMEDIO": "🟡", "AVANCADO": "🔴"}

    if not (isinstance(scenarios, list) and scenarios):
        st.info("Sem cenários disponíveis.")
        return

    for sc in scenarios:
        diff = sc.get("difficulty", "INTERMEDIO")
        questions = sc.get("questions", [])
        with st.expander(
            f"{diff_icons.get(diff, '⚪')} **{sc['title']}** | {diff} | "
            f"⭐ {sc.get('xp_reward', 0)} XP | {len(questions)} questão(ões)"
        ):
            st.write(sc.get("description", ""))
            st.caption(f"Tipo: {sc.get('type', '—')}")
            user_id = _own_user_id(profile_user_id, f"colab_user_sel_{sc['id']}")

            answers = []
            with st.form(f"colab_mission_{sc['id']}"):
                for qi, q in enumerate(questions):
                    ans = st.radio(
                        f"**Q{qi + 1}. {q['question']}**",
                        options=list(range(len(q["options"]))),
                        format_func=lambda x, q=q: q["options"][x],
                        key=f"colab_q_{sc['id']}_{qi}",
                    )
                    answers.append(ans)
                play_btn = st.form_submit_button("🎯 Submeter respostas", use_container_width=True)

            if play_btn:
                result = _api(
                    "post", f"/api/gamification/scenarios/{sc['id']}/submit",
                    json={"user_id": int(user_id), "answers": answers},
                )
                if "error" in result:
                    st.error(result["error"])
                else:
                    score = result.get("score_percentage", 0)
                    xp = result.get("xp_earned", 0)
                    if result.get("passed"):
                        st.success(f"✅ {result.get('feedback', 'Concluído')} | +{xp} XP")
                    else:
                        st.error(f"❌ {result.get('feedback', 'Tenta novamente')}")
                    st.progress(int(score), text=f"Pontuação: {score:.1f}%")
                    with st.expander("📖 Explicações"):
                        for fb in result.get("detailed_feedback", []):
                            icon = "🟢" if fb["is_correct"] else "🔴"
                            st.write(f"{icon} **{fb['question']}**")
                            st.write(f"  A tua resposta: *{fb['your_answer']}*")
                            if not fb["is_correct"]:
                                st.write(f"  Correta: **{fb['correct_answer']}**")
                            st.caption(f"  {fb['explanation']}")
                    for badge in result.get("new_badges", []):
                        st.balloons()
                        st.success(f"🏅 Novo badge: **{badge}**!")
                    st.info(
                        f"XP Total: {result.get('new_xp_total', 0)} | "
                        f"Nível: {result.get('new_level', 1)} | "
                        f"Risk Score: {result.get('new_risk_score', 0):.1f}"
                    )


def _gam_leaderboard() -> None:
    st.subheader("🏆 Tabela de Classificação")
    lb = _api("get", "/api/gamification/leaderboard")
    if not (isinstance(lb, list) and lb):
        st.info("Sem utilizadores na classificação.")
        return
    rank_icons = {1: "🥇", 2: "🥈", 3: "🥉"}
    header = st.columns([0.5, 2, 1, 1, 1.5, 1.5])
    for col, label in zip(header, ["**Pos.**", "**Nome**", "**Nível**", "**XP**", "**Missões**", "**Risk Score**"]):
        col.write(label)
    st.divider()
    for u in lb:
        rank = u.get("rank", 0)
        risk = u.get("risk_score", 50)
        r_color = "🟢" if risk < 30 else "🟡" if risk < 60 else "🔴"
        row = st.columns([0.5, 2, 1, 1, 1.5, 1.5])
        row[0].write(rank_icons.get(rank, f"#{rank}"))
        row[1].write(u.get("full_name", u.get("username", "—")))
        row[2].write(f"⭐ {u.get('level', 1)}")
        row[3].write(f"{u.get('xp_points', 0)} XP")
        row[4].write(f"{u.get('missions_completed', 0)}/{u.get('total_missions', 0)}")
        row[5].write(f"{r_color} {risk:.0f}")


def _gam_reportar(profile_user_id: Optional[int]) -> None:
    st.subheader("🚩 Reportar Email Suspeito")
    st.caption(
        "Reporta um email real suspeito com um clique. O sistema faz triagem automática "
        "e, se a ameaça for provável, gera um incidente no SOCHAI."
    )
    reporter_id = _own_user_id(profile_user_id, "colab_report_user")

    with st.form("colab_phishing_report_form"):
        rp_sender = st.text_input("Remetente *", placeholder="suporte@microsoft-helpdesk.net")
        c1, c2 = st.columns(2)
        rp_subject = c1.text_input("Assunto", placeholder="Urgente: verifique a sua conta agora")
        rp_attachment = c2.checkbox("Contém anexo")
        rp_body = st.text_area("Excerto do corpo do email", height=90)
        rp_urls = st.text_area("URLs presentes no email (uma por linha, opcional)", height=60)
        report_btn = st.form_submit_button("🚩 Reportar ao SOCHAI", use_container_width=True)

    if report_btn:
        if not rp_sender.strip():
            st.error("O remetente é obrigatório.")
            return
        payload = {
            "reporter_id": int(reporter_id),
            "sender": rp_sender,
            "subject": rp_subject,
            "body_snippet": rp_body,
            "urls": [u.strip() for u in rp_urls.splitlines() if u.strip()],
            "has_attachment": rp_attachment,
        }
        result = _api("post", "/api/phishing/report", json=payload)
        if "error" in result:
            st.error(result["error"])
            return
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
            st.success(f"🔗 Incidente **{result['incident_created']}** criado no SOCHAI.")
        c1, c2, c3 = st.columns(3)
        c1.metric("XP ganho", f"+{result.get('xp_awarded', 0)}")
        c2.metric("Risk Score", f"{result.get('new_risk_score', 0):.1f}")
        c3.metric("XP total", result.get("new_xp_total", 0))
        for badge in result.get("new_badges", []):
            st.balloons()
            st.success(f"🏅 Novo badge: **{badge}**!")


def _tab_gamificacao(profile_user_id: Optional[int]) -> None:
    st.subheader("🎮 Formação & Gamificação")
    g_tabs = st.tabs(["🎯 Missões", "🏆 Leaderboard", "🚩 Reportar Email"])
    with g_tabs[0]:
        _gam_missoes(profile_user_id)
    with g_tabs[1]:
        _gam_leaderboard()
    with g_tabs[2]:
        _gam_reportar(profile_user_id)


# ------------------------------------------------------------------ #
# Entrada
# ------------------------------------------------------------------ #

def render(user: dict) -> None:
    profile_user_id = user.get("user_id")

    st.header(f"👋 Bem-vindo, {user.get('name', user.get('username', 'colaborador'))}")
    st.caption(
        "Portal do Colaborador — Gamificação, Playbooks e acompanhamento de incidentes. "
        "Só vês e jogas o teu próprio perfil."
    )

    if profile_user_id is not None:
        profile = _api("get", f"/api/users/{profile_user_id}")
        if isinstance(profile, dict) and "error" not in profile:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Nível", f"⭐ {profile.get('level', 1)}")
            c2.metric("XP", profile.get("xp_points", 0))
            c3.metric("Missões", f"{profile.get('missions_completed', 0)}/{profile.get('total_missions', 0)}")
            c4.metric("Risk Score", f"{profile.get('risk_score', 50):.0f}")
            if profile.get("badges"):
                st.caption("Badges: " + " ".join(f"`{b}`" for b in profile["badges"]))
            st.divider()
    else:
        st.info(
            "ℹ️ Esta conta não está associada a um perfil de gamificação (conta de demonstração)."
        )

    tabs = st.tabs(["🎮 Gamificação", "📋 Playbooks", "🚨 Incidentes"])
    with tabs[0]:
        _tab_gamificacao(profile_user_id)
    with tabs[1]:
        _tab_playbooks()
    with tabs[2]:
        _tab_incidentes()
