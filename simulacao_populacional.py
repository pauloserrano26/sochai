"""
simulacao_populacional.py — Simulação alargada dos cenários de treino de
gamificação (L5), complementar a simulacao_treino.py.

Duas partes, ambas sobre o motor REAL (GamificationEngine), já com a
correção de update_risk_score() aplicada:

1. Percurso individual — um único utilizador ("teste.tese") submetido às
   5 missões base com respostas propositadamente variadas (perfeitas,
   parcial, totalmente erradas), para expor a mecânica de pontuação.

2. Amostra alargada — 15 colaboradores sintéticos, distribuídos por 3
   níveis de competência (probabilidade de responder corretamente por
   pergunta: alto 90%, médio 60%, baixo 30%), correndo os mesmos 5
   cenários e, de seguida, expostos a uma campanha de phishing simulado
   (modelo Cofense/PhishMe). Reprodutível com random.seed(42).

Uso:  python simulacao_populacional.py
"""

import json
import random
from datetime import datetime

from gamification import GamificationEngine, SIM_OUTCOME

SEED = 42
SCENARIO_IDS = ["SC-001", "SC-002", "SC-003", "SC-004", "SC-005"]

engine = GamificationEngine()

# ────────────────────────────────────────────────────────────────────────────
# 1. Percurso individual — respostas controladas (não aleatórias)
# ────────────────────────────────────────────────────────────────────────────
INDIVIDUAL_ANSWERS = {
    "SC-001": [1, 2],     # 2/2 — perfeito
    "SC-002": [1, 1, 0],  # 2/3 — parcial (66.7%)
    "SC-003": [2, 0],     # 2/2 — perfeito
    "SC-004": [0, 1],     # 0/2 — totalmente errado
    "SC-005": [1],        # 1/1 — perfeito
}


def run_individual():
    xp_total = 0
    missions_completed = 0
    risk = 50.0
    rows = []

    for sid in SCENARIO_IDS:
        scenario = engine.get_scenario(sid)
        result = engine.evaluate_mission(INDIVIDUAL_ANSWERS[sid], scenario)
        xp_total += result["xp_earned"]
        if result["passed"]:
            missions_completed += 1
        risk = GamificationEngine.update_risk_score(
            risk, missions_completed, result["score_percentage"], False,
        )
        rows.append({
            "cenario": f"{sid} · {scenario['title']}",
            "dificuldade": scenario["difficulty"],
            "acertos": f"{result['correct']}/{result['total']}",
            "score_pct": result["score_percentage"],
            "xp_ganho": result["xp_earned"],
            "aprovado": result["passed"],
        })

    level = GamificationEngine.calculate_level(xp_total)
    progress = GamificationEngine.xp_to_next_level(xp_total)
    return {
        "utilizador": "teste.tese",
        "rows": rows,
        "xp_total": xp_total,
        "nivel": level,
        "nivel_progress_pct": progress["progress_pct"],
        "nivel_seguinte": level + 1,
        "missions_aprovadas": missions_completed,
        "missions_total": len(SCENARIO_IDS),
        "risk_inicial": 50.0,
        "risk_final": risk,
        "risk_delta_pct": round((risk - 50.0) / 50.0 * 100, 1),
    }


# ────────────────────────────────────────────────────────────────────────────
# 2. Amostra alargada — 15 colaboradores sintéticos, 3 níveis de competência
# ────────────────────────────────────────────────────────────────────────────
SKILL_GROUPS = {
    "alto":  {"p_correct": 0.90, "n": 5},
    "medio": {"p_correct": 0.60, "n": 5},
    "baixo": {"p_correct": 0.30, "n": 5},
}

# Probabilidades de desfecho na campanha de phishing simulado, por nível de
# competência (assunção documentada: maior competência -> mais reportes,
# menos cliques). Usadas apenas na parte 2, não afetam update_risk_score.
PHISHING_BEHAVIOR = {
    "alto":  {"reported": 0.65, "ignored": 0.25, "clicked": 0.10},
    "medio": {"reported": 0.40, "ignored": 0.35, "clicked": 0.25},
    "baixo": {"reported": 0.15, "ignored": 0.35, "clicked": 0.50},
}


def simulate_answers(scenario, p_correct, rng):
    answers = []
    for q in scenario["questions"]:
        if rng.random() < p_correct:
            answers.append(q["correct"])
        else:
            wrong = [i for i in range(len(q["options"])) if i != q["correct"]]
            answers.append(rng.choice(wrong))
    return answers


def pick_outcome(probs, rng):
    r = rng.random()
    cum = 0.0
    for outcome, p in probs.items():
        cum += p
        if r < cum:
            return outcome
    return "ignored"


def run_population():
    rng = random.Random(SEED)

    per_scenario_scores = {g: {sid: [] for sid in SCENARIO_IDS} for g in SKILL_GROUPS}
    risk_by_stage = {g: {"baseline": [], "pos_treino": [], "pos_phishing": []} for g in SKILL_GROUPS}
    phishing_counts = {g: {"reported": 0, "ignored": 0, "clicked": 0} for g in SKILL_GROUPS}
    phishing_times = {g: [] for g in SKILL_GROUPS}

    for group, cfg in SKILL_GROUPS.items():
        for u in range(cfg["n"]):
            risk = 50.0
            missions_completed = 0
            risk_by_stage[group]["baseline"].append(risk)

            for sid in SCENARIO_IDS:
                scenario = engine.get_scenario(sid)
                answers = simulate_answers(scenario, cfg["p_correct"], rng)
                result = engine.evaluate_mission(answers, scenario)
                per_scenario_scores[group][sid].append(result["score_percentage"])
                if result["passed"]:
                    missions_completed += 1
                risk = GamificationEngine.update_risk_score(
                    risk, missions_completed, result["score_percentage"], False,
                )
            risk_by_stage[group]["pos_treino"].append(risk)

            # Campanha de phishing simulado (1 email por colaborador)
            outcome = pick_outcome(PHISHING_BEHAVIOR[group], rng)
            phishing_counts[group][outcome] += 1
            reward = GamificationEngine.reward_for_outcome(outcome, risk)
            risk = reward["new_risk_score"]
            risk_by_stage[group]["pos_phishing"].append(risk)
            if outcome != "pending":
                phishing_times[group].append(round(rng.uniform(15, 240), 1))

    # Agregações
    avg_score_by_scenario = {
        group: {sid: round(sum(v) / len(v), 1) for sid, v in scen.items()}
        for group, scen in per_scenario_scores.items()
    }
    avg_risk_by_stage = {
        group: {stage: round(sum(v) / len(v), 1) for stage, v in stages.items()}
        for group, stages in risk_by_stage.items()
    }

    campaign_stats = {}
    total_reported = total_clicked = total_ignored = 0
    all_times = []
    for group, counts in phishing_counts.items():
        n = SKILL_GROUPS[group]["n"]
        reported, ignored, clicked = counts["reported"], counts["ignored"], counts["clicked"]
        resilience = GamificationEngine.resilience_rate(reported, clicked)
        campaign_stats[group] = {
            "n": n, "reported": reported, "ignored": ignored, "clicked": clicked,
            "resilience_pct": resilience,
        }
        total_reported += reported
        total_clicked += clicked
        total_ignored += ignored
        all_times += phishing_times[group]

    total_n = sum(SKILL_GROUPS[g]["n"] for g in SKILL_GROUPS)
    campaign_overview = {
        "n": total_n,
        "click_rate_pct": round(total_clicked / total_n * 100, 1),
        "report_rate_pct": round(total_reported / total_n * 100, 1),
        "resilience_pct": GamificationEngine.resilience_rate(total_reported, total_clicked),
        "avg_time_seconds": round(sum(all_times) / len(all_times), 1) if all_times else None,
    }

    return {
        "seed": SEED,
        "skill_groups": SKILL_GROUPS,
        "avg_score_by_scenario": avg_score_by_scenario,
        "avg_risk_by_stage": avg_risk_by_stage,
        "campaign_stats": campaign_stats,
        "campaign_overview": campaign_overview,
    }


def print_report(individual, population):
    print("=" * 100)
    print("  PERCURSO INDIVIDUAL —", individual["utilizador"])
    print("=" * 100)
    print(f"{'Cenário':<32}{'Dificuldade':<14}{'Acertos':<10}{'Score':<9}{'XP':<7}Aprovado")
    for r in individual["rows"]:
        print(f"{r['cenario']:<32}{r['dificuldade']:<14}{r['acertos']:<10}"
              f"{r['score_pct']:>5.1f}%  {r['xp_ganho']:<7}{'Sim' if r['aprovado'] else 'Não'}")
    print("-" * 100)
    print(f"  XP acumulado: {individual['xp_total']}   "
          f"Nível: {individual['nivel']} ({individual['nivel_progress_pct']}% p/ nível {individual['nivel_seguinte']})   "
          f"Missões aprovadas: {individual['missions_aprovadas']}/{individual['missions_total']}   "
          f"Risk Score: {individual['risk_inicial']} → {individual['risk_final']} ({individual['risk_delta_pct']}%)")

    print("\n" + "=" * 100)
    print(f"  AMOSTRA ALARGADA — n=15, seed={population['seed']}")
    print("=" * 100)
    print("\nScore médio por cenário e nível de competência:")
    for sid in SCENARIO_IDS:
        vals = " | ".join(f"{g}: {population['avg_score_by_scenario'][g][sid]:>5.1f}%" for g in SKILL_GROUPS)
        print(f"  {sid:<10}{vals}")

    print("\nRisk Score médio por estágio:")
    for g in SKILL_GROUPS:
        st = population["avg_risk_by_stage"][g]
        print(f"  {g:<8} baseline={st['baseline']:>5.1f}  pós-treino={st['pos_treino']:>5.1f}  pós-phishing={st['pos_phishing']:>5.1f}")

    print("\nCampanha de phishing simulado:")
    for g, s in population["campaign_stats"].items():
        print(f"  {g:<8} n={s['n']}  reportou={s['reported']}  ignorou={s['ignored']}  "
              f"clicou={s['clicked']}  resiliência={s['resilience_pct']}%")
    ov = population["campaign_overview"]
    print(f"\n  Global: taxa de cliques={ov['click_rate_pct']}%  taxa de reporte={ov['report_rate_pct']}%  "
          f"resilience rate={ov['resilience_pct']}%  tempo médio até ação={ov['avg_time_seconds']}s")


def main():
    individual = run_individual()
    population = run_population()
    print_report(individual, population)

    out = {"gerado_em": datetime.now().isoformat(), "individual": individual, "populacao": population}
    with open("simulacao_populacional_resultados.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("\nRelatório completo guardado em: simulacao_populacional_resultados.json")


if __name__ == "__main__":
    main()
