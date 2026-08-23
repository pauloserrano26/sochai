"""
simulacao_treino.py — Simulação dos cenários de treino de gamificação (L5),
usada para avaliar o efeito da correção da limitação da base fixa em
update_risk_score() (gamification.py).

Corre uma jornada de missões e simulações de phishing sobre o motor REAL
(GamificationEngine), comparando o resultado com uma cópia do algoritmo
ANTIGO (pré-correção, que ignorava current_score), e valida com um pequeno
conjunto de testes que a correção resolve o problema descrito.

Uso:  python simulacao_treino.py
"""

import json
from datetime import datetime

from gamification import GamificationEngine, SIM_OUTCOME

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"


# ────────────────────────────────────────────────────────────────────────────
# Algoritmo ANTIGO (pré-correção), replicado aqui apenas para comparação.
# Ignorava current_score e recalculava sempre a partir de uma base fixa (50).
# ────────────────────────────────────────────────────────────────────────────
def update_risk_score_legado(current_score, missions_completed, score_percentage, has_security_incidents):
    base = 50.0
    training_reduction = min(missions_completed * 2.5, 30)
    performance_reduction = score_percentage * 0.15
    incident_penalty = 20.0 if has_security_incidents else 0.0
    score = base - training_reduction - performance_reduction + incident_penalty
    return round(max(0.0, min(100.0, score)), 1)


def risk_band(score: float) -> str:
    if score < 20:
        return "BAIXO"
    if score < 50:
        return "MÉDIO"
    return "ALTO"


# ────────────────────────────────────────────────────────────────────────────
# Jornada simulada: um colaborador completa as 5 missões base + 2 simulações
# de phishing, com desempenho realista e variável (não sempre perfeito).
# Cada entrada de "answers" foi construída para produzir a % desejada.
# ────────────────────────────────────────────────────────────────────────────
engine = GamificationEngine()

MISSION_ANSWERS = {
    "SC-001": [1, 2],        # 2/2 correto -> 100%
    "SC-002": [1, 0],        # 1/3 correto -> 33% (desempenho fraco, simula erro real)
    "SC-003": [2, 0],        # 2/2 correto -> 100%
    "SC-004": [1, 0],        # 1/2 correto -> 50%
    "SC-005": [1],           # 1/1 correto -> 100%
}

PHISHING_OUTCOMES = ["reported", "clicked"]


def run_journey():
    """Executa a jornada sobre o motor real e devolve o histórico passo a passo."""
    state_new = {"xp_points": 0, "missions_completed": 0, "risk_score": 50.0, "badges": []}
    state_old = {"missions_completed": 0, "risk_score": 50.0}
    history = []

    for scenario_id, answers in MISSION_ANSWERS.items():
        scenario = engine.get_scenario(scenario_id)
        result = engine.evaluate_mission(answers, scenario)

        state_new["xp_points"] += result["xp_earned"]
        if result["passed"]:
            state_new["missions_completed"] += 1
            state_old["missions_completed"] += 1
        state_new["risk_score"] = GamificationEngine.update_risk_score(
            state_new["risk_score"], state_new["missions_completed"],
            result["score_percentage"], False,
        )
        state_old["risk_score"] = update_risk_score_legado(
            state_old["risk_score"], state_old["missions_completed"],
            result["score_percentage"], False,
        )
        new_badges = engine.check_badges(state_new, result, elapsed_minutes=2.0)
        state_new["badges"] += new_badges

        history.append({
            "step": scenario["title"],
            "type": "missao",
            "score_percentage": result["score_percentage"],
            "passed": result["passed"],
            "xp_earned": result["xp_earned"],
            "risk_score_novo": state_new["risk_score"],
            "risk_score_antigo": state_old["risk_score"],
            "badges": new_badges,
        })

    # Simulação de phishing (usa reward_for_outcome — mecanismo já correto,
    # incluído para cobrir o outro cenário de treino da plataforma)
    for outcome in PHISHING_OUTCOMES:
        reward = GamificationEngine.reward_for_outcome(outcome, state_new["risk_score"])
        state_new["xp_points"] += reward["xp_delta"]
        state_new["risk_score"] = reward["new_risk_score"]
        history.append({
            "step": f"Simulação de phishing ({outcome})",
            "type": "phishing",
            "score_percentage": None,
            "passed": outcome == "reported",
            "xp_earned": reward["xp_delta"],
            "risk_score_novo": state_new["risk_score"],
            "risk_score_antigo": None,
            "badges": [],
        })

    # Incidente de segurança real associado ao colaborador (penalização direta)
    state_new["risk_score"] = GamificationEngine.update_risk_score(
        state_new["risk_score"], state_new["missions_completed"], 0.0, True,
    )
    state_old["risk_score"] = update_risk_score_legado(
        state_old["risk_score"], state_old["missions_completed"], 0.0, True,
    )
    history.append({
        "step": "Incidente de segurança reportado ao colaborador",
        "type": "incidente",
        "score_percentage": None,
        "passed": None,
        "xp_earned": 0,
        "risk_score_novo": state_new["risk_score"],
        "risk_score_antigo": state_old["risk_score"],
        "badges": [],
    })

    return history, state_new, state_old


def print_journey(history):
    print(f"\n{BOLD}{'='*100}{RESET}")
    print(f"{BOLD}  JORNADA DE TREINO SIMULADA — Risk Score: algoritmo NOVO vs ANTIGO (pré-correção){RESET}")
    print(f"{BOLD}{'='*100}{RESET}")
    print(f"{'Passo':<45} {'%':>6} {'XP':>5} {'Score NOVO':>12} {'Score ANTIGO':>13}  Badges")
    print("-" * 100)
    for h in history:
        pct = f"{h['score_percentage']:.0f}%" if h["score_percentage"] is not None else "—"
        old = f"{h['risk_score_antigo']:.1f}" if h["risk_score_antigo"] is not None else "—"
        badges = ", ".join(h["badges"]) if h["badges"] else ""
        print(f"{h['step']:<45} {pct:>6} {h['xp_earned']:>5} {h['risk_score_novo']:>12.1f} {old:>13}  {badges}")
    print("-" * 100)


# ────────────────────────────────────────────────────────────────────────────
# Testes — validam explicitamente o problema descrito e a correção aplicada
# ────────────────────────────────────────────────────────────────────────────
def run_tests():
    passed, failed = 0, 0

    def check(name, condition):
        nonlocal passed, failed
        if condition:
            print(f"  {GREEN}[PASS]{RESET} {name}")
            passed += 1
        else:
            print(f"  {RED}[FAIL]{RESET} {name}")
            failed += 1

    print(f"\n{BOLD}{'='*100}{RESET}")
    print(f"{BOLD}  TESTES — comportamento de update_risk_score(){RESET}")
    print(f"{BOLD}{'='*100}{RESET}")

    # 1. O score fica sempre dentro dos limites [0, 100]
    s = GamificationEngine.update_risk_score(150.0, 3, 200.0, True)
    check("Score é sempre limitado a [0, 100]", 0.0 <= s <= 100.0)

    # 2. BUG ORIGINAL: o algoritmo antigo ignora current_score — dois
    #    utilizadores com históricos completamente diferentes, ao submeterem
    #    o mesmo resultado, ficavam com o MESMO risk score.
    old_a = update_risk_score_legado(80.0, 5, 90.0, False)  # histórico de risco alto
    old_b = update_risk_score_legado(15.0, 5, 90.0, False)  # histórico de risco baixo
    check(
        "Algoritmo ANTIGO ignora o histórico (bug confirmado: mesmo resultado independente de current_score)",
        old_a == old_b,
    )

    # 3. CORREÇÃO: o algoritmo novo usa current_score — os mesmos dois
    #    utilizadores devem agora ficar com scores diferentes.
    new_a = GamificationEngine.update_risk_score(80.0, 5, 90.0, False)
    new_b = GamificationEngine.update_risk_score(15.0, 5, 90.0, False)
    check(
        "Algoritmo NOVO incorpora o histórico (current_score influencia o resultado)",
        new_a != new_b,
    )
    check(
        "Utilizador com histórico de risco mais alto mantém-se acima do de histórico baixo",
        new_a > new_b,
    )

    # 4. Um incidente de segurança deve aumentar o risco de imediato
    base = GamificationEngine.update_risk_score(30.0, 5, 80.0, False)
    with_incident = GamificationEngine.update_risk_score(30.0, 5, 80.0, True)
    check("Incidente de segurança aumenta o risk score", with_incident > base)

    # 5. Sem missões nem desempenho, um utilizador novo mantém-se no valor
    #    inicial (não é empurrado artificialmente para 50 fixo)
    s_new_user = GamificationEngine.update_risk_score(50.0, 0, 0.0, False)
    check("Utilizador novo (sem histórico) mantém-se em torno da base neutra (50)", 45.0 <= s_new_user <= 50.0)

    # 6. Bom desempenho sustentado ao longo de várias missões reduz o risco
    #    de forma consistente (tendência decrescente, não oscilante)
    trend = [50.0]
    for i in range(1, 9):
        trend.append(GamificationEngine.update_risk_score(trend[-1], i, 95.0, False))
    check(
        "Score desce de forma consistente com bom desempenho sustentado",
        all(trend[i] >= trend[i + 1] for i in range(len(trend) - 1)) and trend[-1] < trend[0],
    )

    print("-" * 100)
    print(f"  Resultado: {passed}/{passed + failed} testes passaram")
    print(f"{GREEN}Todos os testes passaram!{RESET}" if failed == 0 else f"{RED}{failed} teste(s) falharam.{RESET}")
    return passed, failed


def main():
    history, state_new, state_old = run_journey()
    print_journey(history)

    print(f"\n{BOLD}RESULTADO FINAL DO COLABORADOR (algoritmo novo){RESET}")
    print(f"  XP total:            {state_new['xp_points']}")
    print(f"  Nível:               {GamificationEngine.calculate_level(state_new['xp_points'])}")
    print(f"  Missões concluídas:  {state_new['missions_completed']}")
    print(f"  Badges:              {', '.join(state_new['badges']) or '—'}")
    print(f"  Risk Score final:    {state_new['risk_score']:.1f}  ({risk_band(state_new['risk_score'])})")
    print(f"\n{BOLD}Comparação final (mesma jornada, algoritmo antigo){RESET}")
    print(f"  Risk Score final (ANTIGO): {state_old['risk_score']:.1f}  ({risk_band(state_old['risk_score'])})")

    passed, failed = run_tests()

    report = {
        "gerado_em": datetime.now().isoformat(),
        "jornada": history,
        "resultado_final_novo": {
            "xp_points": state_new["xp_points"],
            "nivel": GamificationEngine.calculate_level(state_new["xp_points"]),
            "missions_completed": state_new["missions_completed"],
            "badges": state_new["badges"],
            "risk_score": state_new["risk_score"],
            "risk_band": risk_band(state_new["risk_score"]),
        },
        "resultado_final_antigo": {
            "risk_score": state_old["risk_score"],
            "risk_band": risk_band(state_old["risk_score"]),
        },
        "testes": {"passaram": passed, "falharam": failed},
    }
    out_path = "simulacao_treino_resultados.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n{CYAN}Relatório completo guardado em: {out_path}{RESET}")


if __name__ == "__main__":
    main()
