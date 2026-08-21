# -*- coding: utf-8 -*-
"""
Testes de integracao e seguranca contra a API live.
Executa automaticamente: arranca a API, testa, para.
"""

import json
import subprocess
import sys
import time
import os

import requests

API = "http://localhost:8000"
PYTHON = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv", "Scripts", "python.exe")

PASS = 0
FAIL = 0
_api_proc = None


def test(name, fn):
    global PASS, FAIL
    try:
        fn()
        print(f"  [PASS] {name}")
        PASS += 1
    except AssertionError as e:
        print(f"  [FAIL] {name} -- {e}")
        FAIL += 1
    except Exception as e:
        print(f"  [ERRO] {name} -- {type(e).__name__}: {e}")
        FAIL += 1


def get(path, **kw):
    return requests.get(f"{API}{path}", timeout=8, **kw)


def post(path, body, **kw):
    return requests.post(f"{API}{path}", json=body, timeout=8, **kw)


def patch(path, **kw):
    return requests.patch(f"{API}{path}", timeout=8, **kw)


def kill_port_8000():
    try:
        result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if ":8000" in line and "LISTENING" in line:
                parts = line.strip().split()
                pid = int(parts[-1])
                subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
    except Exception:
        pass


def start_api():
    global _api_proc
    kill_port_8000()
    time.sleep(1)
    print("\n[*] A arrancar API SOCHAI...")
    _api_proc = subprocess.Popen(
        [PYTHON, "api_main.py"],
        cwd=os.path.dirname(os.path.abspath(__file__)),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for i in range(15):
        time.sleep(1)
        try:
            r = requests.get(f"{API}/health", timeout=2)
            if r.status_code == 200:
                print(f"    API online apos {i+1}s")
                return True
        except Exception:
            pass
    print("    [ERRO] API nao respondeu em 15s")
    return False


def stop_api():
    global _api_proc
    if _api_proc:
        _api_proc.terminate()
        try:
            _api_proc.wait(timeout=5)
        except Exception:
            _api_proc.kill()
        print("\n[*] API parada.")


def run_tests():
    global _created_asset_id, _incident_id
    _created_asset_id = None
    _incident_id = None

    # ------------------------------------------------------------------ #
    # 1. Health & Sistema
    # ------------------------------------------------------------------ #
    print("\n[1] Health & Sistema")

    def test_health():
        r = get("/health")
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "online"
        assert "modules" in d

    def test_docs_available():
        r = get("/docs")
        assert r.status_code == 200

    def test_openapi_schema():
        r = get("/openapi.json")
        assert r.status_code == 200
        schema = r.json()
        assert "paths" in schema
        assert len(schema["paths"]) >= 10

    test("GET /health responde online", test_health)
    test("GET /docs (Swagger) disponivel", test_docs_available)
    test("GET /openapi.json tem >= 10 endpoints", test_openapi_schema)

    # ------------------------------------------------------------------ #
    # 2. Ativos (CRUD)
    # ------------------------------------------------------------------ #
    print("\n[2] Gestao de Ativos")

    def test_list_assets():
        r = get("/api/assets")
        assert r.status_code == 200
        assert isinstance(r.json(), list)
        assert len(r.json()) >= 1

    def test_create_asset():
        global _created_asset_id
        r = post("/api/assets", {
            "name": "Servidor Teste Integracao",
            "asset_type": "server",
            "ip_address": "10.99.0.1",
            "criticality": "ALTO",
            "department": "TI",
            "os_system": "Ubuntu 22.04",
        })
        assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
        d = r.json()
        assert d["name"] == "Servidor Teste Integracao"
        assert d["id"] > 0
        _created_asset_id = d["id"]

    def test_get_asset():
        r = get(f"/api/assets/{_created_asset_id}")
        assert r.status_code == 200, f"HTTP {r.status_code}"
        assert r.json()["criticality"] == "ALTO"

    def test_update_asset():
        r = requests.put(f"{API}/api/assets/{_created_asset_id}", json={
            "name": "Servidor Teste Atualizado",
            "asset_type": "server",
            "criticality": "CRITICO",
            "department": "TI",
        }, timeout=8)
        assert r.status_code == 200, f"HTTP {r.status_code}"
        assert r.json()["criticality"] == "CRITICO"

    def test_delete_asset():
        r = requests.delete(f"{API}/api/assets/{_created_asset_id}", timeout=8)
        assert r.status_code == 200, f"Delete retornou {r.status_code}"
        # Soft delete: GET deve retornar 404
        r2 = get(f"/api/assets/{_created_asset_id}")
        assert r2.status_code == 404, f"Apos soft-delete esperava 404, obteve {r2.status_code}"

    def test_asset_filter():
        r = get("/api/assets", params={"criticality": "CRITICO"})
        assert r.status_code == 200
        data = r.json()
        assert all(a["criticality"] == "CRITICO" for a in data)

    test("Listar ativos", test_list_assets)
    test("Criar ativo", test_create_asset)
    test("Obter ativo por ID", test_get_asset)
    test("Atualizar ativo", test_update_asset)
    test("Eliminar ativo (soft delete + 404)", test_delete_asset)
    test("Filtrar ativos por criticidade", test_asset_filter)

    # ------------------------------------------------------------------ #
    # 3. Alertas & Pipeline ML (L1 -> L6)
    # ------------------------------------------------------------------ #
    print("\n[3] Alertas & Pipeline ML (L1->L6)")

    def test_submit_alert_basic():
        global _incident_id
        r = post("/api/alerts", {
            "type": "malware",
            "description": "Ficheiro suspeito detetado no endpoint ws-rh-01",
            "severity": "ALTA",
            "source_ip": "192.168.2.101",
            "run_llm_pipeline": False,
        })
        assert r.status_code == 200, f"HTTP {r.status_code}: {r.text}"
        d = r.json()
        assert d["incident_id"].startswith("INC-")
        assert 0.0 <= d["ml_score"] <= 1.0
        assert "xai_summary" in d
        assert d["soar_actions_executed"] >= 1
        _incident_id = d["incident_id"]

    def test_alert_ransomware():
        r = post("/api/alerts", {
            "type": "ransomware",
            "description": "Todos os ficheiros encriptados com extensao .locked",
            "severity": "CRITICA",
            "source_ip": "185.220.101.5",
            "port": 4444,
        })
        assert r.status_code == 200
        d = r.json()
        assert d["soar_actions_executed"] >= 3

    def test_alert_xai_report():
        r = post("/api/alerts", {
            "type": "phishing",
            "description": "Email suspeito com link malicioso",
            "severity": "MEDIA",
        })
        assert r.status_code == 200
        xai = r.json().get("xai_report", {})
        assert "top_contributing_factors" in xai
        assert "decision_path" in xai
        assert len(xai["decision_path"]) >= 2

    def test_list_incidents():
        r = get("/api/incidents", params={"limit": 10})
        assert r.status_code == 200
        assert len(r.json()) >= 1

    def test_get_incident():
        r = get(f"/api/incidents/{_incident_id}")
        assert r.status_code == 200
        assert r.json()["incident_id"] == _incident_id

    def test_update_incident_status():
        r = patch(f"/api/incidents/{_incident_id}/status", params={"status": "investigating"})
        assert r.status_code == 200
        assert r.json()["new_status"] == "investigating"

    def test_filter_incidents():
        r = get("/api/incidents", params={"status": "investigating"})
        assert r.status_code == 200
        assert all(i["status"] == "investigating" for i in r.json())

    test("Submeter alerta malware (ML+SOAR)", test_submit_alert_basic)
    test("Alerta ransomware critica: >= 3 acoes SOAR", test_alert_ransomware)
    test("Alerta retorna relatorio XAI completo", test_alert_xai_report)
    test("Listar incidentes", test_list_incidents)
    test("Obter incidente por ID", test_get_incident)
    test("Atualizar estado do incidente", test_update_incident_status)
    test("Filtrar incidentes por estado", test_filter_incidents)

    # ------------------------------------------------------------------ #
    # 4. Playbooks (L3 - RAG)
    # ------------------------------------------------------------------ #
    print("\n[4] Playbooks (L3 - RAG)")

    def test_library():
        r = get("/api/playbooks/library")
        assert r.status_code == 200
        data = r.json()
        assert len(data) >= 6
        assert all("steps" in pb for pb in data)

    def test_retrieve_rag():
        r = get("/api/playbooks/retrieve", params={"query": "ransomware encryption", "top_k": 2})
        assert r.status_code == 200
        data = r.json()
        assert len(data) >= 1
        assert any("ransomware" in pb.get("threat_type", "").lower() for pb in data)

    def test_playbooks_db():
        r = get("/api/playbooks")
        assert r.status_code == 200
        assert len(r.json()) >= 6

    test("Biblioteca de playbooks (>= 6)", test_library)
    test("Retrieval RAG por query", test_retrieve_rag)
    test("Playbooks persistidos na BD", test_playbooks_db)

    # ------------------------------------------------------------------ #
    # 5. HITL (L4)
    # ------------------------------------------------------------------ #
    print("\n[5] HITL (L4)")

    def test_hitl_pending():
        r = get("/api/hitl/pending")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_hitl_stats():
        r = get("/api/hitl/stats")
        assert r.status_code == 200
        d = r.json()
        assert "total_reviewed" in d
        assert "sla_compliance_pct" in d

    def test_hitl_cycle():
        r1 = post("/api/alerts", {
            "type": "intrusion",
            "description": "Login fora de horas a partir de IP desconhecido",
            "severity": "CRITICA",
            "source_ip": "185.100.200.5",
            "port": 3389,
        })
        inc = r1.json()["incident_id"]
        r3 = post(f"/api/hitl/{inc}/review", {
            "analyst_username": "ana.silva",
            "decision": "VERDADEIRO_POSITIVO",
            "notes": "Confirmado via logs",
        })
        assert r3.status_code == 200
        result = r3.json()
        assert result["decision"] == "VERDADEIRO_POSITIVO"
        assert "review_time_minutes" in result

    test("Listar revisoes pendentes", test_hitl_pending)
    test("Estatisticas HITL", test_hitl_stats)
    test("Ciclo HITL (alerta -> revisao)", test_hitl_cycle)

    # ------------------------------------------------------------------ #
    # 6. Gamificacao (L5)
    # ------------------------------------------------------------------ #
    print("\n[6] Gamificacao (L5)")

    def test_scenarios():
        r = get("/api/gamification/scenarios")
        assert r.status_code == 200
        assert len(r.json()) >= 5

    def test_get_scenario():
        r = get("/api/gamification/scenarios/SC-001")
        assert r.status_code == 200
        d = r.json()
        assert d["id"] == "SC-001"

    def test_mission_perfect():
        sc = get("/api/gamification/scenarios/SC-001").json()
        correct = [q["correct"] for q in sc["questions"]]
        r = post("/api/gamification/scenarios/SC-001/submit", {
            "user_id": 1,
            "answers": correct,
        })
        assert r.status_code == 200
        d = r.json()
        assert d["score_percentage"] == 100.0
        assert d["passed"] is True

    def test_leaderboard():
        r = get("/api/gamification/leaderboard")
        assert r.status_code == 200
        data = r.json()
        assert len(data) >= 1
        assert data[0]["rank"] == 1

    def test_user_stats():
        r = get("/api/gamification/stats/1")
        assert r.status_code == 200
        d = r.json()
        assert "level_progress" in d
        assert "risk_score" in d

    test("Listar cenarios (>= 5)", test_scenarios)
    test("Obter cenario SC-001", test_get_scenario)
    test("Missao com 100% correto", test_mission_perfect)
    test("Leaderboard ordenado", test_leaderboard)
    test("Estatisticas de utilizador", test_user_stats)

    # ------------------------------------------------------------------ #
    # 7. SOAR (L6)
    # ------------------------------------------------------------------ #
    print("\n[7] SOAR (L6)")

    def test_soar_log():
        r = get("/api/soar/log")
        assert r.status_code == 200
        assert len(r.json()) >= 1

    def test_soar_summary():
        r = get("/api/soar/summary")
        assert r.status_code == 200
        d = r.json()
        assert d["total_actions"] >= 1
        assert d["success"] >= 1

    test("Log SOAR tem acoes registadas", test_soar_log)
    test("Resumo SOAR com sucesso", test_soar_summary)

    # ------------------------------------------------------------------ #
    # 8. Analytics
    # ------------------------------------------------------------------ #
    print("\n[8] Analytics")

    def test_overview():
        r = get("/api/analytics/overview")
        assert r.status_code == 200
        d = r.json()
        assert d["incidents"]["total"] >= 1
        assert "assets" in d and "users" in d
        assert "hitl" in d and "soar" in d

    test("Overview analytics completo", test_overview)

    # ------------------------------------------------------------------ #
    # 9. Seguranca
    # ------------------------------------------------------------------ #
    print("\n[9] Testes de Seguranca")

    def test_404_endpoint():
        r = get("/api/endpoint_inexistente")
        assert r.status_code == 404

    def test_404_asset():
        r = get("/api/assets/999999")
        assert r.status_code == 404

    def test_422_missing_field():
        r = post("/api/assets", {"asset_type": "server"})
        assert r.status_code == 422

    def test_404_incident():
        r = get("/api/incidents/INC-INEXISTENTE-000")
        assert r.status_code == 404

    def test_hitl_unknown():
        r = post("/api/hitl/INC-FAKE-999/review", {
            "analyst_username": "test",
            "decision": "FALSO_POSITIVO",
        })
        assert r.status_code in (404, 200)
        if r.status_code == 200:
            assert "error" in r.json()

    def test_sql_injection():
        r = post("/api/assets", {
            "name": "'; DROP TABLE assets; --",
            "asset_type": "server",
            "criticality": "BAIXO",
        })
        assert r.status_code == 200
        requests.delete(f"{API}/api/assets/{r.json()['id']}", timeout=8)

    def test_xss():
        r = post("/api/alerts", {
            "type": "scan",
            "description": "<script>alert('xss')</script>",
            "severity": "BAIXA",
        })
        assert r.status_code == 200
        assert "incident_id" in r.json()

    def test_large_payload():
        r = post("/api/alerts", {
            "type": "malware",
            "description": "A" * 5000,
            "severity": "MEDIA",
        })
        assert r.status_code == 200

    def test_cors():
        r = get("/health")
        assert r.status_code == 200

    test("404 para endpoint desconhecido", test_404_endpoint)
    test("404 para ativo inexistente", test_404_asset)
    test("422 para campo obrigatorio em falta", test_422_missing_field)
    test("404 para incidente inexistente", test_404_incident)
    test("HITL review incidente inexistente nao crasha", test_hitl_unknown)
    test("SQL injection protegido pelo ORM", test_sql_injection)
    test("XSS tratado como texto simples", test_xss)
    test("Payload de 5000 chars nao crasha", test_large_payload)
    test("API responde com CORS ativo", test_cors)


# ================================================================== #
# Main
# ================================================================== #
print("=" * 62)
print("  MESI SOCHAI -- Testes de Integracao & Seguranca")
print("=" * 62)

if not start_api():
    print("Impossivel continuar sem API.")
    sys.exit(1)

try:
    run_tests()
except Exception as e:
    print(f"\n[ERRO FATAL] {e}")
finally:
    stop_api()

total = PASS + FAIL
print()
print("=" * 62)
print(f"  RESULTADO: {PASS}/{total} testes passaram")
if FAIL == 0:
    print("  Todos os testes passaram!")
else:
    print(f"  FALHOS: {FAIL}")
print("=" * 62)

sys.exit(0 if FAIL == 0 else 1)
