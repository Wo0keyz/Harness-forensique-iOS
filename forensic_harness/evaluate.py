"""Évaluation : rejoue le graphe sur un cas à vérité terrain et mesure ce qu'il produit.

    python -m forensic_harness.evaluate --dataset datasets/magnet_ground_truth.json --case <dossier> --runs 5
    python -m forensic_harness.evaluate --dataset … --score runs/<cas>/<exécution> [...]   # sans modèle
    python -m forensic_harness.evaluate --dataset … --report ancien_rapport.md             # texte libre
    python -m forensic_harness.evaluate --dataset … --case <dossier> --audit               # vérifie le jeu

Ce que les mesures disent, et ne disent pas :
- rappel : un fait compte s'il figure dans un constat vérifié ET dans une preuve que ce constat
  cite. C'est une mesure de repérage et de citation, pas de compréhension : un modèle qui recopie
  les bonnes lignes l'obtient. Elle se lit avec « faits par constat » (un constat qui empile des
  mots-clés s'y voit) et avec la source exacte ;
- source exacte : parmi les faits retrouvés, part dont la preuve vient de l'export attendu ;
- plafond de rappel : part des faits présents dans les preuves transmises, depuis l'export attendu.
  Ce qui manque ici est un défaut d'extraction, pas de raisonnement ;
- citations valides : part des constats du modèle acceptés par le contrôle automatique (validité
  de forme, pas vérité), au premier essai et après relance ;
- accusations inventées (cas témoin) : constats affirmant un terme interdit par le jeu de données.
"""

import argparse
import asyncio
import json
import os
import re
import statistics
import sys
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from forensic_harness import config
from forensic_harness.extract import DOMAINS, record_text

DUMP_THRESHOLD = 3  # un constat qui couvre autant de faits distincts est un empilement de mots-clés
_NEGATION = r"\b(?:aucun|aucune|pas|ni|sans|rien|absence|jamais|non)\b"


def _asserted(term: str, text: str) -> bool:
    """Le terme est-il affirmé ? Oui, sauf si une négation le précède à trois mots au plus, sans ponctuation
    entre les deux : « n'a pas volé », « n'a jamais été volé », mais pas « sans scrupule, a volé »."""
    return any(
        not re.search(_NEGATION + r"(?:[\s'’-]+[^\W\d]+){0,3}[\s'’-]*$", text[: m.start()])
        for m in re.finditer(re.escape(term), text)
    )


_NUMBER = re.compile(r"(?<![\w.])\+?\d[\d ().\-]{4,}\d(?!\w)")


def _norm(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).replace("’", "'").replace("‘", "'")
    return re.sub(r"\s+", " ", text).casefold()


def matches(spec: Any, text: str) -> bool:
    """`text` est déjà normalisé. Règle : chaîne (mot entier), `digits:…`, `re:…`, {all: [...]} ou {any: [...]}."""
    if isinstance(spec, dict):
        return (all if "all" in spec else any)(matches(s, text) for s in spec.get("all", spec.get("any", [])))
    if spec.startswith("digits:"):  # un même numéro, quels que soient ses séparateurs et son indicatif
        target = spec[7:]
        digits = (re.sub(r"\D", "", number) for number in _NUMBER.findall(text))
        return any(d.endswith(target) and len(d) <= len(target) + 3 for d in digits)
    if spec.startswith("re:"):  # expression régulière, pour une valeur dont seul le début est fixé
        return re.search(spec[3:], text) is not None
    return re.search(rf"(?<!\w){re.escape(_norm(spec))}(?!\w)", text) is not None


def matches_any_part(spec: Any, text: str) -> bool:
    """Une preuve « porte » un fait composé (règle all) dès qu'elle en contient une partie."""
    if isinstance(spec, dict) and "all" in spec:
        return any(matches_any_part(s, text) for s in spec["all"])
    return matches(spec, text)


def _evidence(extraction: dict) -> dict[str, tuple[str, str]]:
    """Référence → (nom du fichier d'export, texte normalisé de la preuve)."""
    return {
        r["tag"]: (r["source_file"].rsplit("/", 1)[-1], _norm(record_text(r)))
        for e in extraction["sources"].values()
        for r in e["records"]
    }


def score_findings(
    dataset: dict, results: dict[str, dict], extraction: dict, report: list[dict] | None = None
) -> dict[str, Any]:
    """Mesures d'une exécution à partir de findings.json et extraction.json.

    `results` : agent → {"verified", "rejected", …} pour tous les appels au modèle (validité des
    citations). `report` : les constats imprimés dans le rapport principal, sur lesquels portent
    le rappel et les accusations ; à défaut, tous les constats vérifiés.
    """
    evidence = _evidence(extraction)
    verified = [f for res in results.values() for f in res["verified"]]
    rejected = [f for res in results.values() for f in res["rejected"]]
    shown = verified if report is None else report
    texts = [(_norm(f"{f.get('titre', '')} {f['claim']} {f['quote']}"), f) for f in shown]

    items: dict[str, dict[str, Any]] = {}
    per_finding = [0] * len(texts)
    for gt in dataset["ground_truth_concordance_table"]:
        expected = set(gt.get("source_files", []))
        stated = grounded = source_ok = False
        for n, (text, f) in enumerate(texts):
            if not matches(gt["match"], text):
                continue
            stated = True
            per_finding[n] += 1
            cited = [evidence[t] for t in f["evidence"] if t in evidence]
            if matches(gt["match"], " ".join(body for _, body in cited)):
                grounded = True
                source_ok = source_ok or any(
                    name in expected and matches_any_part(gt["match"], body) for name, body in cited
                )
        items[gt["id"]] = {
            "stated": stated,  # le fait est écrit dans un constat vérifié
            "found": grounded,  # … et figure dans une preuve que ce constat cite
            "source_ok": (source_ok if expected else None) if grounded else None,
            "judgement": bool(gt.get("judgement")),
        }

    found = [i for i in items.values() if i["found"]]
    strict = [i for i in items.values() if not i["judgement"]]
    sourced = [i for i in found if i["source_ok"] is not None]
    first = [res["first_attempt"] for res in results.values() if res.get("first_attempt")]
    emitted_first = sum(a["verified"] + a["rejected"] for a in first)
    total = len(verified) + len(rejected)
    forbidden = [_norm(t) for t in dataset.get("forbidden_terms", [])]
    accusations = sorted({f["claim"] for text, f in texts if any(_asserted(t, text) for t in forbidden)})
    calls = [c for res in results.values() for c in res.get("calls", [])]
    return {
        "items": items,
        "recall": len(found) / len(items),
        "recall_strict": sum(i["found"] for i in strict) / len(strict),
        "recall_text_only": sum(i["stated"] for i in items.values()) / len(items),
        "source_accuracy": (sum(bool(i["source_ok"]) for i in sourced) / len(sourced)) if sourced else None,
        "findings_verified": len(verified),
        "findings_in_report": len(shown),
        "findings_rejected": len(rejected),
        "citation_validity": len(verified) / total if total else None,
        "first_attempt_validity": (sum(a["verified"] for a in first) / emitted_first)
        if emitted_first
        else None,
        "no_evidence_rate": (
            sum(1 for f in rejected if any("sans preuve valide" in r for r in f["reasons"])) / total
            if total
            else None
        ),
        "unreadable_answers": sum(res.get("unreadable", 0) for res in results.values()),
        "max_facts_per_finding": max(per_finding, default=0),
        "keyword_dumps": sum(n >= DUMP_THRESHOLD for n in per_finding),
        "kinds": {k: sum(f["kind"] == k for f in verified) for k in ("fait", "inference", "hypothese")},
        "invented_accusations": accusations,
        "model_seconds": round(sum(c.get("seconds") or 0 for c in calls), 1),
        "completion_tokens": sum(c.get("completion_tokens") or 0 for c in calls),
        "model_calls": len(calls),
        "cached_calls": sum(bool(c.get("cached")) for c in calls),
    }


def reachable(dataset: dict, extraction: dict) -> dict[str, bool]:
    """Pour chaque fait : figure-t-il dans les preuves transmises au modèle, depuis un export attendu ?

    Un fait hors d'atteinte ne peut pas être retrouvé, quel que soit le modèle : c'est un défaut
    d'extraction (source non lue, fenêtre de dates), pas de raisonnement.
    """
    evidence = list(_evidence(extraction).values())
    out = {}
    for gt in dataset["ground_truth_concordance_table"]:
        expected = set(gt.get("source_files", []))
        blob = " ".join(body for name, body in evidence if not expected or name in expected)
        out[gt["id"]] = matches(gt["match"], blob)
    return out


def _flatten(data: dict) -> tuple[dict[str, dict], list[dict] | None, list[dict], dict]:
    """findings.json → (tous les appels, constats du rapport ou None, enquêtes, résultats bruts).

    Ancien format (avant l'enquête) : findings.json est directement {agent: résultat}.
    """
    if "results" not in data:
        return data, None, [], data
    results, enquetes = data["results"], data.get("enquetes", [])
    agents = dict(results)
    for e in enquetes:
        n = e["scenario"]["n"]
        agents[f"instruction.{n}"] = e["instruction"]
        agents[f"contradiction.{n}"] = e["contradiction"]
    return agents, None, enquetes, results


def score_scenarios(dataset: dict, results: dict, enquetes: list[dict], extraction: dict) -> dict[str, Any]:
    """Scénarios attendus (jeu de données) retrouvés parmi les scénarios retenus de l'exécution.

    Un scénario attendu est retrouvé si un scénario retenu (étayé ou à vérifier) le décrit
    (`match` sur les constats vérifiés : hypothèse, éléments à charge, récit et qualifications ; le titre,
    non vérifié, ne compte pas) ET si les preuves citées par les constats qui portent `match` contiennent
    `evidence_match`.
    """
    evidence = _evidence(extraction)
    kept = [e for e in enquetes if e["verdict"] in ("etaye", "fragile")]
    story = results.get("redaction", {}).get("verified", [])
    quals = results.get("qualification", {}).get("verified", [])
    items = {}
    for spec in dataset.get("scenarios", []):
        hit = None
        for e in kept:
            n = e["scenario"]["n"]
            findings = [
                e["scenario"],
                *[f for f in e["instruction"]["verified"] if f.get("sens") == "charge"],
                *[f for f in story if f.get("section") == "recit" and f.get("scenario") == n],
                *[f for f in quals if f.get("scenario") == n],
            ]
            said = [(f, _norm(f"{f['claim']} {f['quote']}")) for f in findings]
            text = " ".join(t for _, t in said)
            carriers = [f for f, t in said if matches_any_part(spec["match"], t)]
            cited = " ".join(evidence[t][1] for f in carriers for t in f["evidence"] if t in evidence)
            if matches(spec["match"], text) and matches(spec["evidence_match"], cited):
                hit = {"scenario": n, "verdict": e["verdict"]}
                break
        items[spec["id"]] = hit
    return {
        "scenario_items": items,
        "scenario_recall": (sum(v is not None for v in items.values()) / len(items)) if items else None,
        "scenarios_retained": len(kept),
        "scenarios_examined": len(enquetes),
        "qualifications": sorted({f["qualification"] for f in quals}),
    }


def score_run(dataset: dict, run_dir: Path, force: bool = False) -> dict[str, Any]:
    data = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    extraction = json.loads((run_dir / "extraction.json").read_text(encoding="utf-8"))
    meta = run_dir / "run.json"
    expected = dataset.get("target_case", {}).get("case_dir_name")
    if expected and not force:
        if not meta.exists():
            raise ValueError(
                f"{run_dir} : run.json absent, impossible de savoir quel cas a été analysé (--force)"
            )
        actual = Path(json.loads(meta.read_text(encoding="utf-8"))["case"]).name
        if actual != expected:
            raise ValueError(
                f"{run_dir} analyse le cas « {actual} », le jeu de données porte sur « {expected} » "
                "(--force pour noter quand même)"
            )
    agents, _, enquetes, results = _flatten(data)
    report = None
    reading_recall = None
    if "results" in data:
        from forensic_harness.report import rendered_findings

        report = rendered_findings(extraction, results, enquetes)
        reading = {d: results[d] for d in DOMAINS if d in results}
        reading_recall = score_findings(dataset, reading, extraction)["recall"]
    within_reach = reachable(dataset, extraction)
    return {
        "run_dir": str(run_dir),
        **score_findings(dataset, agents, extraction, report),
        "recall_reading": reading_recall,
        **score_scenarios(dataset, results, enquetes, extraction),
        "unreachable": [i for i, ok in within_reach.items() if not ok],
        "recall_ceiling": sum(within_reach.values()) / len(within_reach),
    }


def score_report_text(dataset: dict, text: str) -> dict[str, Any]:
    """Présence des faits dans un rapport en texte libre (ancien harness) : aucune traçabilité à mesurer."""
    norm = _norm(text)
    items = {
        gt["id"]: {"stated": matches(gt["match"], norm), "judgement": bool(gt.get("judgement"))}
        for gt in dataset["ground_truth_concordance_table"]
    }
    strict = [i for i in items.values() if not i["judgement"]]
    return {
        "items": items,
        "recall_text_only": sum(i["stated"] for i in items.values()) / len(items),
        "recall_text_only_strict": sum(i["stated"] for i in strict) / len(strict),
    }


def audit_dataset(dataset: dict, case: Path) -> list[str]:
    """Le jeu de données tient-il face au dossier ? Chaque export cité doit exister et contenir le fait."""
    problems = []
    exports = {p.name: p for p in case.rglob("*.tsv")}
    for gt in dataset["ground_truth_concordance_table"]:
        if not gt.get("source_files"):
            problems.append(f"{gt['id']} : aucun export attendu (source_files vide)")
        for name in gt.get("source_files", []):
            if name not in exports:
                problems.append(f"{gt['id']} : export cité absent du dossier : {name}")
            elif not gt.get("judgement"):
                text = _norm(exports[name].read_text(encoding="utf-8-sig", errors="replace"))
                if not matches_any_part(gt["match"], text):
                    problems.append(
                        f"{gt['id']} : {name} ne contient pas le fait (règle de détection introuvable)"
                    )
        if gt.get("judgement"):
            problems.append(f"{gt['id']} : fait d'appréciation, non vérifiable automatiquement (information)")
    return problems


MEASURES = (
    "scenario_recall", "scenarios_retained", "scenarios_examined", "recall_reading", "findings_in_report",
    "recall", "recall_strict", "recall_text_only", "recall_ceiling", "source_accuracy", "citation_validity",
    "first_attempt_validity", "no_evidence_rate", "max_facts_per_finding", "keyword_dumps", "unreadable_answers",
    "invented_accusations", "model_seconds", "findings_verified", "findings_rejected", "cached_calls",
)  # fmt: skip


def aggregate(dataset: dict, runs: list[dict[str, Any]]) -> dict[str, Any]:
    def spread(key: str) -> dict[str, Any]:
        raw = [len(r[key]) if isinstance(r.get(key), list) else r.get(key) for r in runs]
        values = [v for v in raw if v is not None]
        if not values:
            return {"mean": None, "min": None, "max": None, "stdev": None, "n": 0}
        return {
            "mean": round(statistics.mean(values), 3),
            "min": round(min(values), 3),
            "max": round(max(values), 3),
            "stdev": round(statistics.stdev(values), 3) if len(values) > 1 else None,
            "n": len(values),  # exécutions où la mesure existe (une exécution sans constat n'en a pas)
        }

    ids = [gt["id"] for gt in dataset["ground_truth_concordance_table"]]
    return {
        "dataset": dataset["dataset_name"],
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
        "model": config.MODEL,
        "runs": len(runs),
        **{k: spread(k) for k in MEASURES},
        "per_item_hit_rate": {
            i: round(sum(r["items"][i]["found"] for r in runs) / len(runs), 2) for i in ids
        },
        "per_scenario_hit_rate": {
            sc["id"]: round(
                sum(r.get("scenario_items", {}).get(sc["id"]) is not None for r in runs) / len(runs), 2
            )
            for sc in dataset.get("scenarios", [])
        },
        "qualifications_seen": sorted({q for r in runs for q in r.get("qualifications", [])}),
        "details": runs,
    }


def summary_table(agg: dict[str, Any]) -> str:
    def cell(key: str, pct: bool = True) -> str:
        v = agg[key]
        if v["mean"] is None:
            return "n/a (aucune exécution mesurable)"
        fmt = (lambda x: f"{x:.0%}") if pct else (lambda x: f"{x:g}")
        text = fmt(v["mean"]) + (f" ({fmt(v['min'])}–{fmt(v['max'])})" if agg["runs"] > 1 else "")
        return text + (f" — sur {v['n']} exécution(s) seulement" if v["n"] < agg["runs"] else "")

    rows = [
        f"Jeu : {agg['dataset']} — modèle : {agg['model']} — exécutions : {agg['runs']}",
        "| Mesure | Valeur |",
        "| :--- | :--- |",
        f"| Scénarios attendus retrouvés (retenus, preuves à l'appui) | {cell('scenario_recall')} |",
        f"| Scénarios retenus par exécution (cas témoin : 0 attendu) | {cell('scenarios_retained', pct=False)} |",
        f"| Scénarios examinés par exécution | {cell('scenarios_examined', pct=False)} |",
        f"| Rappel du rapport principal (fait énoncé et présent dans une preuve citée) | {cell('recall')} |",
        f"| Rappel de la lecture (tous les constats vérifiés) | {cell('recall_reading')} |",
        f"| Rappel hors faits d'appréciation | {cell('recall_strict')} |",
        f"| Fait seulement énoncé dans le texte (sans exiger la preuve) | {cell('recall_text_only')} |",
        f"| Plafond de rappel (faits présents dans les preuves transmises) | {cell('recall_ceiling')} |",
        f"| Source exacte parmi les faits retrouvés | {cell('source_accuracy')} |",
        f"| Citations valides (après relance) | {cell('citation_validity')} |",
        f"| Citations valides au premier essai | {cell('first_attempt_validity')} |",
        f"| Constats émis sans preuve valide | {cell('no_evidence_rate')} |",
        f"| Réponses illisibles par exécution | {cell('unreadable_answers', pct=False)} |",
        f"| Faits couverts par un même constat (max) | {cell('max_facts_per_finding', pct=False)} |",
        f"| Constats « empilement de mots-clés » par exécution | {cell('keyword_dumps', pct=False)} |",
        f"| Accusations inventées par exécution (cas témoin) | {cell('invented_accusations', pct=False)} |",
        f"| Constats vérifiés par exécution | {cell('findings_verified', pct=False)} |",
        f"| Constats imprimés dans le rapport principal | {cell('findings_in_report', pct=False)} |",
        f"| Temps de modèle par exécution (s) | {cell('model_seconds', pct=False)} |",
    ]
    out_of_reach = sorted({i for r in agg["details"] for i in r.get("unreachable", [])})
    missed = [i for i, rate in agg["per_item_hit_rate"].items() if rate < 1]
    rows += [
        "",
        "Faits hors d'atteinte (absents des preuves transmises) : " + (", ".join(out_of_reach) or "aucun"),
        "Faits non retrouvés à chaque exécution : "
        + (", ".join(f"{i} ({agg['per_item_hit_rate'][i]:.0%})" for i in missed) or "aucun"),
    ]
    if agg.get("per_scenario_hit_rate"):
        rows.append(
            "Scénarios attendus : "
            + ", ".join(f"{i} ({rate:.0%})" for i, rate in agg["per_scenario_hit_rate"].items())
        )
    rows.append("Qualifications envisagées : " + (", ".join(agg.get("qualifications_seen", [])) or "aucune"))
    if agg["runs"] == 1:
        rows.append("Une seule exécution : aucune mesure de stabilité. Relancer avec --runs 3 ou plus.")
    return "\n".join(rows)


def gate(agg: dict[str, Any], thresholds: dict[str, dict[str, float]]) -> list[str]:
    """Seuils de non-régression sur les moyennes : {"min": {mesure: plancher}, "max": {mesure: plafond}}.

    Une mesure absente ou non mesurable sur une exécution fait échouer le seuil.
    """
    failures = []
    for kind, limits in thresholds.items():
        if kind not in ("min", "max") or not isinstance(limits, dict):
            failures.append(f"clé de seuil inconnue : {kind!r} (attendu : min, max)")
            continue
        for key, limit in limits.items():
            if not isinstance(limit, int | float):
                failures.append(f"seuil non numérique pour {key} : {limit!r}")
                continue
            v = agg.get(key)
            if not isinstance(v, dict) or v["mean"] is None or v["n"] < agg["runs"]:
                failures.append(f"{key} non mesurable sur toutes les exécutions")
            elif (kind == "min" and v["mean"] < limit) or (kind == "max" and v["mean"] > limit):
                failures.append(f"{key} = {v['mean']} ({'<' if kind == 'min' else '>'} {limit})")
    return failures


def push_langfuse(dataset: dict[str, Any], run_dir: Path, score: dict[str, Any]) -> None:
    """Inscrit l'exécution notée dans Langfuse : jeu de données, item du cas, passage, mesures.

    Langfuse n'exécute pas le graphe (local, plusieurs heures) : il range et trace ce que l'évaluation a mesuré.
    Le jeu et son item sont mis à jour sur place ; noter deux fois la même exécution ajoute un essai au même passage.
    Rien du dossier n'est envoyé hors des mesures, des identifiants de faits et des chemins.
    """
    if not os.getenv("LANGFUSE_PUBLIC_KEY"):
        return
    try:
        from langfuse import Evaluation, get_client

        client = get_client()
        name = dataset["dataset_name"]
        case = dataset.get("target_case", {}).get("case_dir_name") or name
        client.create_dataset(name=name, description=dataset.get("description"))
        client.create_dataset_item(
            dataset_name=name,
            id=f"{name}:{case}",
            input={"case": case},
            expected_output={
                "facts": [gt["id"] for gt in dataset["ground_truth_concordance_table"]],
                "scenarios": [sc["id"] for sc in dataset.get("scenarios", [])],
                "forbidden_terms": dataset.get("forbidden_terms", []),
            },
        )
        meta = run_dir / "run.json"
        manifest = run_dir / "manifest.json"
        values = {
            k: (len(v) if isinstance(v, list) else v) for k in MEASURES if (v := score.get(k)) is not None
        }
        # le graphe ne tourne pas dans Langfuse : la « tâche » rend les mesures déjà calculées, ce qui suffit au SDK
        # pour marquer la trace comme expérience (seule source des vues d'expérience en Langfuse v4)
        client.get_dataset(name).run_experiment(
            name=name,
            run_name=run_dir.name,
            description=f"{run_dir.parent.name}/{run_dir.name}",
            task=lambda *, item, **_: values,
            evaluators=[
                lambda *, output, **_: [Evaluation(name=k, value=float(v)) for k, v in output.items() if isinstance(v, int | float)]
            ],
            metadata={
                "model": config.MODEL,
                "commit": json.loads(manifest.read_text(encoding="utf-8"))["code"]["harness"]["commit"][:7]
                if manifest.exists() else None,
                "run_trace_id": json.loads(meta.read_text(encoding="utf-8")).get("langfuse_trace_id")
                if meta.exists() else None,
            },
        )  # fmt: skip
        client.flush()
    except Exception as e:  # l'évaluation ne doit pas échouer parce que Langfuse est arrêté
        print(f"(mesures non envoyées à Langfuse : {e})", file=sys.stderr)


async def run_once(case: Path) -> Path:
    from forensic_harness.__main__ import run  # import tardif : charge le graphe

    run_dir, _ = await run(str(case))
    return run_dir


def _main(args: argparse.Namespace, ap: argparse.ArgumentParser) -> int:
    dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
    facts = dataset.get("ground_truth_concordance_table")
    if not facts or any("match" not in gt for gt in facts):
        raise ValueError("jeu de données sans faits, ou fait sans règle `match`")
    if (args.audit or args.runs) and not (args.case and args.case.is_dir()):
        ap.error("--case <dossier iLEAPP existant> est requis avec --audit et --runs")

    if args.audit:
        problems = audit_dataset(dataset, args.case)
        print("\n".join(problems) or "Jeu de données cohérent avec le dossier.")
        return 1 if any("(information)" not in p for p in problems) else 0
    if args.report:
        score = score_report_text(dataset, args.report.read_text(encoding="utf-8"))
        print(
            f"Faits énoncés dans le texte : {score['recall_text_only']:.0%} "
            f"(hors appréciation : {score['recall_text_only_strict']:.0%})"
        )
        print("Non énoncés :", ", ".join(i for i, v in score["items"].items() if not v["stated"]) or "aucun")
        print(
            "ATTENTION : texte libre, donc aucune traçabilité mesurée. Une simple liste de mots-clés obtiendrait "
            "100 %. Ce chiffre ne se compare qu'à la ligne « seulement énoncé » d'une exécution notée."
        )
        return 0

    async def run_all() -> list[Path]:
        # une seule boucle pour toutes les exécutions : le client HTTP partagé de langchain-openai garde
        # ses connexions d'une exécution à l'autre, et une boucle fermée entre deux les rend inutilisables
        done = []
        for n in range(args.runs):
            print(f"[{n + 1}/{args.runs}] exécution du graphe sur {args.case} …", flush=True)
            done.append(await run_once(args.case))
        return done

    if args.runs > 1 and config.LLM_CACHE:  # n exécutions relues du cache n'en font qu'une : dispersion nulle
        print("cache des réponses coupé pour mesurer la dispersion entre exécutions", flush=True)
        config.LLM_CACHE = ""
    run_dirs = list(args.score) + (asyncio.run(run_all()) if args.runs else [])
    if not run_dirs:
        ap.error("rien à noter : donner --runs N (avec --case) ou --score <dossier d'exécution>")
    scores = [score_run(dataset, d, args.force) for d in run_dirs]
    for run_dir, score in zip(run_dirs, scores, strict=True):
        push_langfuse(dataset, run_dir, score)
    agg = aggregate(dataset, scores)
    args.out.mkdir(parents=True, exist_ok=True)
    out = args.out / f"{dataset['dataset_name']}_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    out.write_text(json.dumps(agg, ensure_ascii=False, indent=1), encoding="utf-8")
    print(summary_table(agg))
    print(f"\nDétail : {out}")
    if args.gate:
        failures = gate(agg, json.loads(args.gate.read_text(encoding="utf-8")))
        if failures:
            print("SEUILS NON TENUS : " + " ; ".join(failures), file=sys.stderr)
            return 1
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(prog="forensic_harness.evaluate", description=__doc__.split("\n")[0])
    ap.add_argument("--dataset", required=True, type=Path)
    ap.add_argument("--case", type=Path, help="dossier iLEAPP à analyser (pour --runs et --audit)")
    ap.add_argument("--runs", type=int, default=0, help="nombre d'exécutions du graphe à lancer puis noter")
    ap.add_argument(
        "--score", type=Path, nargs="*", default=[], help="dossiers d'exécution déjà produits à noter"
    )
    ap.add_argument("--report", type=Path, help="rapport en texte libre : faits énoncés seulement")
    ap.add_argument("--audit", action="store_true", help="vérifie le jeu de données contre le dossier")
    ap.add_argument("--gate", type=Path, help="fichier JSON de seuils ; code de sortie 1 si non tenus")
    ap.add_argument(
        "--force", action="store_true", help="noter une exécution d'un autre cas que celui du jeu"
    )
    ap.add_argument("--out", type=Path, default=config.ROOT / "eval_results")
    args = ap.parse_args()
    try:
        sys.exit(_main(args, ap))
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
    ) as e:  # fichier absent, JSON illisible, jeu mal formé
        print(f"Erreur : {type(e).__name__} : {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
