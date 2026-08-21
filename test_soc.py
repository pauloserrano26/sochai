# -*- coding: utf-8 -*-
"""
Test suite for MESI SOCHAI Platform.
Tests all modules that do NOT require live API keys.
"""

import sys
import traceback

PASS = 0
FAIL = 0

def test(name, fn):
    global PASS, FAIL
    try:
        fn()
        print(f"  [PASS] {name}")
        PASS += 1
    except Exception as e:
        print(f"  [FAIL] {name}")
        print(f"         {type(e).__name__}: {e}")
        FAIL += 1


print("=" * 60)
print("  MESI SOCHAI Platform -- Test Suite")
print("=" * 60)

# ------------------------------------------------------------------ #
# 1. Database
# ------------------------------------------------------------------ #
print("\n[1] Database (SQLAlchemy / SQLite)")

import database as db

def test_tables_created():
    from sqlalchemy import inspect
    insp = inspect(db.engine)
    tables = set(insp.get_table_names())
    for t in ("assets", "users", "incidents", "playbooks",
              "gamification_missions", "user_missions", "telemetry_logs"):
        assert t in tables, f"Tabela em falta: {t}"

def test_seed_data():
    s = db.SessionLocal()
    try:
        assert s.query(db.User).count() >= 1, "Nenhum utilizador seed"
        assert s.query(db.Asset).count() >= 1, "Nenhum ativo seed"
        assert s.query(db.Playbook).count() >= 1, "Nenhum playbook seed"
    finally:
        s.close()

def test_create_incident():
    s = db.SessionLocal()
    try:
        inc = db.Incident(
            incident_id="TEST-001",
            title="Teste Importacao",
            severity="MEDIA",
            status="open",
        )
        s.add(inc)
        s.commit()
        found = s.query(db.Incident).filter_by(incident_id="TEST-001").first()
        assert found is not None
        s.delete(found)
        s.commit()
    finally:
        s.close()

test("Tabelas criadas", test_tables_created)
test("Dados seed presentes", test_seed_data)
test("Criar/apagar incidente", test_create_incident)

# ------------------------------------------------------------------ #
# 2. ML Detection
# ------------------------------------------------------------------ #
print("\n[2] ML Detection (L2 - Isolation Forest)")

from ml_detection import ml_detector

def test_ml_normal():
    score, is_anomaly, expl = ml_detector.detect({
        "type": "scan", "severity": "BAIXA", "description": "Port scan detected"
    })
    assert 0.0 <= score <= 1.0, f"Score fora de range: {score}"
    assert isinstance(is_anomaly, bool)
    assert "feature_contributions" in expl

def test_ml_critical():
    score, is_anomaly, expl = ml_detector.detect({
        "type": "ransomware", "severity": "CRITICA",
        "source_ip": "185.220.101.1", "port": 4444,
        "description": "Multiple encrypted files detected after suspicious connection",
    })
    assert 0.0 <= score <= 1.0
    assert "risk_factors" in expl
    assert len(expl["risk_factors"]) > 0

def test_ml_features():
    score, _, expl = ml_detector.detect({"type": "malware", "severity": "ALTA"})
    feats = expl["feature_contributions"]
    assert "hora_dia" in feats
    assert "nivel_severidade" in feats

test("Detetar alerta normal", test_ml_normal)
test("Detetar alerta critica", test_ml_critical)
test("Features presentes na explicacao", test_ml_features)

# ------------------------------------------------------------------ #
# 3. Playbook Engine (RAG only — no LLM call)
# ------------------------------------------------------------------ #
print("\n[3] Playbook Engine (L3 - RAG retrieval)")

from playbook_engine import playbook_engine

def test_retrieve_malware():
    results = playbook_engine.retrieve("malware virus infected system", top_k=1)
    assert len(results) >= 1
    assert "steps" in results[0]

def test_retrieve_phishing():
    results = playbook_engine.retrieve("phishing email credential theft", top_k=2)
    assert any("phishing" in pb.get("threat_type", "").lower() for pb in results)

def test_library_not_empty():
    lib = playbook_engine.get_library()
    assert len(lib) >= 6

def test_retrieve_returns_steps():
    r = playbook_engine.retrieve("ransomware encryption files locked")
    assert r[0]["steps"]
    assert len(r[0]["steps"]) >= 5

test("Retrieval malware", test_retrieve_malware)
test("Retrieval phishing", test_retrieve_phishing)
test("Biblioteca tem >= 6 playbooks", test_library_not_empty)
test("Playbook tem steps", test_retrieve_returns_steps)

# ------------------------------------------------------------------ #
# 4. XAI + HITL
# ------------------------------------------------------------------ #
print("\n[4] XAI + HITL (L4)")

from xai_hitl import xai_explainer, hitl_manager

def test_xai_explain():
    ml_result = {
        "anomaly_score": 0.75, "is_anomaly": True,
        "decision_summary": "ANOMALIA CRITICA",
        "confidence": "Alta (>80%)",
        "feature_contributions": {
            "hora_dia": 3.0, "nivel_severidade": 4.0, "porta_suspeita": 1.0,
            "fora_horario_laboral": 1.0, "score_tipo_ameaca": 5.0,
        },
        "risk_factors": ["Porta suspeita", "Horario fora do normal"],
        "recommended_action": "ESCALADA IMEDIATA",
    }
    report = xai_explainer.explain({"type": "malware", "severity": "ALTA"}, ml_result)
    assert "top_contributing_factors" in report
    assert "decision_path" in report
    assert report["requires_hitl"] is True

def test_hitl_queue():
    ml_r = {"anomaly_score": 0.8, "is_anomaly": True}
    xai_r = {
        "decision_path": ["step1"], "top_contributing_factors": [],
        "risk_factors": [], "recommended_action": "ESCALADA",
        "human_readable_summary": "test", "hitl_sla_minutes": 15,
        "requires_hitl": True,
    }
    hitl_manager.request_review("INC-TEST-XAI", {"type": "malware"}, xai_r, ml_r)
    pending = hitl_manager.get_pending()
    assert any(r["incident_id"] == "INC-TEST-XAI" for r in pending)

def test_hitl_submit():
    result = hitl_manager.submit_review(
        "INC-TEST-XAI", "ana.silva", "VERDADEIRO_POSITIVO", "Confirmado via logs"
    )
    assert result["decision"] == "VERDADEIRO_POSITIVO"
    assert result["analyst_username"] == "ana.silva"
    assert "review_time_minutes" in result

def test_hitl_stats():
    stats = hitl_manager.stats()
    assert "total_reviewed" in stats
    assert "sla_compliance_pct" in stats

test("XAI gera explicacao", test_xai_explain)
test("HITL adiciona a fila", test_hitl_queue)
test("HITL submete revisao", test_hitl_submit)
test("HITL stats", test_hitl_stats)

# ------------------------------------------------------------------ #
# 5. SOAR
# ------------------------------------------------------------------ #
print("\n[5] SOAR Executor (L6)")

from soar_executor import soar_executor

def test_soar_plan_media():
    actions = soar_executor.plan("INC-001", "malware", "MEDIA")
    ids = [a["action_id"] for a in actions]
    assert "create_ticket" in ids
    assert "block_ip" in ids

def test_soar_plan_critica():
    actions = soar_executor.plan("INC-002", "ransomware", "CRITICA")
    ids = [a["action_id"] for a in actions]
    assert "notify_management" in ids
    assert "activate_ir_team" in ids
    assert "emergency_backup" in ids

def test_soar_execute():
    actions = soar_executor.plan("INC-003", "phishing", "ALTA")
    results = soar_executor.execute("INC-003", actions)
    assert len(results) > 0
    assert all(r["status"] == "simulated_success" for r in results)

def test_soar_log():
    log = soar_executor.get_log("INC-003")
    assert len(log) > 0
    assert all(e["incident_id"] == "INC-003" for e in log)

test("Plano SOAR severidade MEDIA", test_soar_plan_media)
test("Plano SOAR severidade CRITICA + ransomware", test_soar_plan_critica)
test("Execucao SOAR retorna resultados", test_soar_execute)
test("Log SOAR por incidente", test_soar_log)

# ------------------------------------------------------------------ #
# 6. Gamification
# ------------------------------------------------------------------ #
print("\n[6] Gamification (L5)")

from gamification import gamification_engine, GamificationEngine

def test_scenarios_loaded():
    scenarios = gamification_engine.get_scenarios()
    assert len(scenarios) >= 5

def test_filter_by_difficulty():
    iniciante = gamification_engine.get_scenarios("INICIANTE")
    assert all(s["difficulty"] == "INICIANTE" for s in iniciante)

def test_evaluate_mission():
    sc = gamification_engine.get_scenario("SC-001")
    assert sc is not None
    # All correct answers
    answers = [q["correct"] for q in sc["questions"]]
    result = gamification_engine.evaluate_mission(answers, sc)
    assert result["score_percentage"] == 100.0
    assert result["passed"] is True
    assert result["xp_earned"] == sc["xp_reward"]

def test_evaluate_mission_fail():
    sc = gamification_engine.get_scenario("SC-002")
    # All wrong answers
    answers = [(q["correct"] + 1) % 4 for q in sc["questions"]]
    result = gamification_engine.evaluate_mission(answers, sc)
    assert result["score_percentage"] < 70
    assert result["passed"] is False

def test_level_calculation():
    assert GamificationEngine.calculate_level(0) == 1
    assert GamificationEngine.calculate_level(100) == 2
    assert GamificationEngine.calculate_level(5001) == 8

def test_risk_score():
    score = GamificationEngine.update_risk_score(50.0, 10, 90.0, False)
    assert 0 <= score <= 100
    assert score < 50  # training should reduce it

def test_xp_progress():
    progress = GamificationEngine.xp_to_next_level(150)
    assert "progress_pct" in progress
    assert 0 <= progress["progress_pct"] <= 100

test("Cenarios carregados (>= 5)", test_scenarios_loaded)
test("Filtrar por dificuldade", test_filter_by_difficulty)
test("Pontuar missao (100% correto)", test_evaluate_mission)
test("Pontuar missao (0% correto)", test_evaluate_mission_fail)
test("Calculo de nivel", test_level_calculation)
test("Calculo de risk score", test_risk_score)
test("Progresso XP para nivel", test_xp_progress)

# ------------------------------------------------------------------ #
# 7. Phishing Report (Cofense/PhishMe model) — L5 -> L1
# ------------------------------------------------------------------ #
print("\n[7] Phishing Report (colaborador -> SOCHAI)")

def test_triage_malicious():
    t = gamification_engine.triage_report({
        "sender": "suporte@microsoft-helpdesk.net",
        "subject": "URGENTE: verifique a sua conta agora",
        "body_snippet": "Atualize imediatamente ou sera suspensa",
        "urls": ["http://bit.ly/x"], "has_attachment": False,
    })
    assert t["verdict"] == "malicious"
    assert t["threat_score"] >= 60
    assert t["requires_soc_review"] is True

def test_triage_benign():
    t = gamification_engine.triage_report({
        "sender": "colega@empresa.pt", "subject": "Reuniao amanha",
        "body_snippet": "Confirmo as 10h", "urls": [], "has_attachment": False,
    })
    assert t["verdict"] == "benign"

def test_report_reward():
    r = GamificationEngine.reward_for_report("malicious", 50.0)
    assert r["xp_awarded"] == 100
    assert r["new_risk_score"] == 42.0  # reportar reduz o risco humano

def test_report_badges():
    b = gamification_engine.check_report_badges({"badges": []}, 1, 0)
    assert "SENTINELA" in b
    b2 = gamification_engine.check_report_badges({"badges": ["SENTINELA"]}, 12, 10)
    assert "OLHO_VIGILANTE" in b2

def test_phishing_report_table():
    from sqlalchemy import inspect
    assert "phishing_reports" in inspect(db.engine).get_table_names()

test("Triagem deteta phishing malicioso", test_triage_malicious)
test("Triagem aceita email benigno", test_triage_benign)
test("Recompensa reduz risco humano", test_report_reward)
test("Badges de sentinela atribuidos", test_report_badges)
test("Tabela phishing_reports existe", test_phishing_report_table)

# ---- Phishing Simulation (medir comportamento real) ----
def test_sim_outcome_clicked():
    r = gamification_engine.reward_for_outcome("clicked", 50.0)
    assert r["new_risk_score"] == 60.0       # clicar aumenta o risco
    assert r["needs_teachable_moment"] is True

def test_sim_outcome_reported():
    r = gamification_engine.reward_for_outcome("reported", 50.0)
    assert r["new_risk_score"] == 43.0       # reportar reduz o risco
    assert r["xp_delta"] == 80

def test_resilience_rate():
    assert gamification_engine.resilience_rate(8, 2) == 80.0
    assert gamification_engine.resilience_rate(0, 0) is None
    assert gamification_engine.resilience_rate(0, 5) == 0.0

def test_campaign_metrics():
    targets = [
        {"outcome": "clicked", "time_to_action_seconds": 30},
        {"outcome": "reported", "time_to_action_seconds": 15},
        {"outcome": "reported", "time_to_action_seconds": 20},
        {"outcome": "ignored", "time_to_action_seconds": None},
    ]
    m = gamification_engine.campaign_metrics(targets)
    assert m["resilience_rate_pct"] == 66.7
    assert m["click_rate_pct"] == 25.0

def test_sim_tables_exist():
    from sqlalchemy import inspect
    tabs = inspect(db.engine).get_table_names()
    assert "phishing_campaigns" in tabs
    assert "phishing_targets" in tabs

test("Simulacao: clicar aumenta risco", test_sim_outcome_clicked)
test("Simulacao: reportar reduz risco", test_sim_outcome_reported)
test("Resilience rate calculado", test_resilience_rate)
test("Metricas de campanha agregadas", test_campaign_metrics)
test("Tabelas de simulacao existem", test_sim_tables_exist)

# ------------------------------------------------------------------ #
# Final summary
# ------------------------------------------------------------------ #
print()
print("=" * 60)
total = PASS + FAIL
print(f"  Resultado: {PASS}/{total} testes passaram")
if FAIL:
    print(f"  FALHOS: {FAIL}")
else:
    print("  Todos os testes passaram!")
print("=" * 60)

sys.exit(0 if FAIL == 0 else 1)
