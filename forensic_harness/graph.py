"""Graphe d'enquête.

    START → extraction → fiche du terminal (code) + lecture (communications, activité, en parallèle)
          → hypothèses ──(aucun scénario)──────────────────────────────┐
                 └──Send : une enquête par scénario (instruction ⇄ contradiction) ─┤
          → qualification → rédaction → [validation de l'analyste] → rapport → END

Toutes les données du cas viennent du serveur iLEAPP-MCP : l'extraction lit les exports par nom
exact, l'enquête interroge le dossier avec des outils en lecture seule. Chaque constat de chaque
agent cite des références `E<n>` que le code vérifie (`validate`). Le rapport principal ne contient
que des constats vérifiés ; les preuves qu'il cite sont renumérotées `P<n>` et décrites dans
preuves.json, à côté du rapport.
"""

import asyncio
import json
import logging
import operator
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from forensic_harness import config, manifest, prompts
from forensic_harness.budget import Budget, measure
from forensic_harness.extract import (
    DOMAINS,
    cited_chronology,
    domain_chunks,
    evidence_index,
    extract_case,
    has_data,
    load_extraction,
    record_line,
    save_extraction,
)
from forensic_harness.investigate import build_enquete, scenario_block
from forensic_harness.llm import empty, merge, overhead, run_agent
from forensic_harness.mcp import open_case
from forensic_harness.profile import terminal_findings
from forensic_harness.report import evidence_file, finding_line, render
from forensic_harness.validate import _norm

logger = logging.getLogger(__name__)

NO_DATA = "Aucune donnée exploitable n'a été extraite pour ce domaine : aucun appel au modèle."
NO_SIGNAL = "Aucun signal autre que de contexte : aucun scénario à formuler, aucun appel au modèle."
RETAINED = ("etaye", "fragile")


class State(TypedDict, total=False):
    case_path: str
    run_dir: str
    since: str | None  # fenêtre de dates facultative (ISO)
    until: str | None
    budget: dict[str, Any]  # contexte mesuré sur le serveur d'inférence
    # décision de l'analyste avant le rapport : {"status": "approved" | "rejected", "analyst", "note", "at"}
    review: dict[str, Any] | None
    # lecture : domaine → {"verified": [...], "rejected": [...], "limits": str, …} ; puis "hypotheses",
    # "qualification", "redaction" ; les preuves restent sur disque
    results: Annotated[dict[str, dict[str, Any]], operator.or_]
    enquetes: Annotated[list[dict[str, Any]], operator.add]
    errors: Annotated[list[str], operator.add]
    final_report: str


# --- lecture -------------------------------------------------------------------------------------


def reading_prompts(domain: str, extraction: dict, budget: Budget) -> list[tuple[str, str, set[str]]]:
    """Un prompt par lot de données du domaine : [(system, user, références du lot)]."""
    spec = prompts.READING[domain]
    chunks = domain_chunks(
        extraction,
        domain,
        budget.chunk_chars(spec["max_tokens"], overhead(spec) + len(prompts.READING_RULES)),
    )
    out = []
    for i, (data, tags) in enumerate(chunks, start=1):
        part = (
            f" Ceci est le lot {i} sur {len(chunks)} : ne conclus que sur ce que tu vois ici."
            if len(chunks) > 1
            else ""
        )
        user = (
            f"Voici les données extraites du terminal. Chaque ligne commence par sa référence.{part}"
            f"\n\n{data}\n\n{prompts.INTEGRITY_RULE}\n\n{spec['task']}\n\n{prompts.READING_RULES}"
            f"\n\n{prompts.OUTPUT_RULES}"
        )
        out.append((spec["system"], user, tags))
    return out


def _signal_ok(f: dict[str, Any]) -> str | None:
    return None if f.get("signal") in prompts.SIGNALS else "catégorie de signal absente ou inconnue"


async def reduce_findings(
    agent: str, result: dict[str, Any], index: dict, budget: Budget, run_dir: str
) -> tuple[dict[str, Any], list[str]]:
    """Condense, pour l'enquête seulement, un domaine qui a produit trop de constats.

    `verified` garde tous les constats vérifiés ; la version courte va dans `condensed`.
    """
    verified = result["verified"]
    if len(verified) <= config.MAX_FINDINGS:
        return result, []
    room = budget.chunk_chars(prompts.REDUCE["max_tokens"], overhead(prompts.REDUCE), whole_context=True)
    groups: list[list[dict]] = [[]]
    used = 0
    for f in verified:
        size = len(signal_line(f)) + 1
        if used + size > room and groups[-1]:
            groups.append([])
            used = 0
        groups[-1].append(f)
        used += size
    keep = max(5, config.MAX_FINDINGS // len(groups))
    weakest = {"fait": 0, "inference": 1, "hypothese": 2}
    kept: list[dict] = []
    rejected, calls, problems = [], [], []
    for i, group in enumerate(groups, start=1):
        user = (
            "=== CONSTATS VÉRIFIÉS ===\n"
            + "\n".join(signal_line(f) for f in group)
            + f"\n\n{prompts.REDUCE['task'].format(keep=keep)}\n\n{prompts.READING_RULES}\n\n{prompts.OUTPUT_RULES}"
        )
        allowed = {t for f in group for t in f["evidence"]}
        part, p = await run_agent(
            f"{agent}.condense{i}", prompts.REDUCE["system"], user, prompts.REDUCE["max_tokens"], index,
            allowed, run_dir, prompts.READING_FORMAT, check=_signal_ok, reading=True,
        )  # fmt: skip
        problems += p
        calls += part["calls"]
        rejected += part["rejected"]
        if not part["verified"]:  # condensation ratée pour ce groupe : ses constats sont gardés tels quels
            kept += group
            problems.append(
                f"{agent} : condensation du groupe {i} sans résultat, {len(group)} constats gardés tels quels"
            )
            continue
        for f in part["verified"]:
            # un constat condensé ne peut pas être plus affirmatif que ceux dont il reprend les preuves
            sources = [g["kind"] for g in group if set(g["evidence"]) & set(f["evidence"])]
            floor = max(sources, key=weakest.__getitem__)
            if weakest[f["kind"]] < weakest[floor]:
                f = {**f, "kind": floor}
            kept.append(f)
    return {
        **result,
        "condensed": kept,
        "rejected": result["rejected"] + rejected,
        "calls": result["calls"] + calls,
    }, problems


def signal_line(f: dict[str, Any]) -> str:
    return f"[{f.get('signal', 'contexte')}] {finding_line(f)}"


def make_reader(domain: str):
    async def node(state: State) -> dict:
        extraction = load_extraction(state["run_dir"])
        if not has_data(extraction, domain):  # pas de données : pas d'appel, donc pas d'invention
            return {"results": {domain: empty(NO_DATA)}}
        budget = Budget(**state["budget"])
        index = evidence_index(extraction)
        batches = reading_prompts(domain, extraction, budget)
        outs = await asyncio.gather(
            *(
                run_agent(
                    domain if len(batches) == 1 else f"{domain}.{i}",
                    system,
                    user,
                    prompts.READING[domain]["max_tokens"],
                    index,
                    tags,
                    state["run_dir"],
                    prompts.READING_FORMAT,
                    check=_signal_ok,
                    reading=True,
                )  # fmt: skip
                for i, (system, user, tags) in enumerate(batches, start=1)
            )
        )
        result, problems = await reduce_findings(
            domain, merge([r for r, _ in outs]), index, budget, state["run_dir"]
        )
        return {"results": {domain: result}, "errors": [p for _, ps in outs for p in ps] + problems}

    return node


async def node_terminal(state: State) -> dict:
    """Fiche du terminal et signaux d'applications relevés par le code dans les exports (aucun appel au modèle)."""
    found = terminal_findings(load_extraction(state["run_dir"]))
    result = empty("" if found else NO_DATA)
    result["verified"] = found
    return {"results": {"terminal": result}}


# --- hypothèses ----------------------------------------------------------------------------------


def _ts_of(f: dict[str, Any], index: dict) -> str:
    stamps = [index[t]["ts"] for t in f["evidence"] if t in index and index[t]["ts"]]
    return min(stamps, default="9999")


def signals(results: dict[str, dict], index: dict) -> tuple[list[dict], list[dict]]:
    """(signaux de comportement, constats de contexte), chacun dans l'ordre du temps."""
    found = [
        f
        for d in DOMAINS
        for f in results.get(d, {}).get("condensed", results.get(d, {}).get("verified", []))
    ]
    found.sort(key=lambda f: _ts_of(f, index))
    return [f for f in found if f.get("signal") != "contexte"], [
        f for f in found if f.get("signal") == "contexte"
    ]


def _block(lines: list[str], room: int, what: str) -> tuple[list[str], list[str]]:
    """Lignes qui tiennent dans `room` caractères, et l'anomalie si certaines n'ont pas tenu."""
    kept, used = [], 0
    for line in lines:
        if used + len(line) + 1 > room:
            break
        kept.append(line)
        used += len(line) + 1
    if len(kept) < len(lines):
        kept.append(f"(PARTIEL : {len(lines) - len(kept)} autres {what} ne t'ont pas été transmis)")
        return kept, [f"{what} : {len(kept) - 1} sur {len(lines)} transmis (contexte plein)"]
    return kept, []


def hypotheses_prompt(
    extraction: dict, results: dict, budget: Budget
) -> tuple[str, set[str], list[str], int]:
    """(prompt, références transmises, anomalies, nombre de signaux de comportement)."""
    index = evidence_index(extraction)
    behaviour, context = signals(results, index)
    room = budget.chunk_chars(
        prompts.HYPOTHESES["max_tokens"], overhead(prompts.HYPOTHESES), whole_context=True
    )
    sig, notes = _block([signal_line(f) for f in behaviour], room // 3, "signaux")
    ctx, notes2 = _block([signal_line(f) for f in context], room // 6, "constats de contexte")
    shown = [f for f in behaviour + context if signal_line(f) in set(sig) | set(ctx)]
    cited = [f["evidence"] for f in shown]  # signaux de comportement d'abord, puis le contexte
    evidence, tags = cited_chronology(index, cited, max(2000, room - sum(map(len, sig + ctx))))
    user = (
        f"=== SIGNAUX DE COMPORTEMENT RELEVÉS À LA LECTURE (ordre du temps) ===\n{chr(10).join(sig) or '(aucun)'}\n\n"
        f"=== CONTEXTE (terminal, utilisateur, relations) ===\n{chr(10).join(ctx) or '(aucun)'}\n\n"
        f"=== PREUVES CITÉES PAR CES CONSTATS (UTC) ===\n{evidence}\n\n"
        f"{prompts.INTEGRITY_RULE}\n\n{prompts.HYPOTHESES['task']}\n\n{prompts.OUTPUT_RULES}"
    )
    # un signal montré a déjà été vérifié contre ses preuves : elles restent citables même si la place
    # a manqué pour les recopier
    return user, tags | {t for f in shown for t in f["evidence"]}, notes + notes2, len(behaviour)


async def node_hypotheses(state: State) -> dict:
    extraction = load_extraction(state["run_dir"])
    user, allowed, notes, n_signals = hypotheses_prompt(
        extraction, state.get("results", {}), Budget(**state["budget"])
    )
    if not n_signals:  # rien qui sorte de l'ordinaire : pas d'appel, donc pas de scénario inventé
        return {"results": {"hypotheses": empty(NO_SIGNAL)}}

    def check(f: dict[str, Any]) -> str | None:
        if not f.get("titre"):
            return "scénario sans titre"
        if len(f["evidence"]) < 2:
            return "un scénario relie au moins deux preuves"
        return None

    result, problems = await run_agent(
        "hypotheses", prompts.HYPOTHESES["system"], user, prompts.HYPOTHESES["max_tokens"],
        evidence_index(extraction), allowed, state["run_dir"], prompts.HYPOTHESES_FORMAT, check=check,
    )  # fmt: skip
    if len(result["verified"]) > config.MAX_SCENARIOS:
        problems.append(
            f"hypothèses : {len(result['verified'])} scénarios, seuls les {config.MAX_SCENARIOS} premiers sont instruits"
        )
    for n, f in enumerate(result["verified"], start=1):
        f["n"] = n
        f["kind"] = "hypothese"  # un scénario reste une hypothèse, quoi qu'en dise le modèle
        f["questions"] = [q for q in f.get("questions", []) if isinstance(q, str)][:4]
    return {"results": {"hypotheses": result}, "errors": notes + problems}


def route_scenarios(state: State) -> list[Send] | str:
    scenarios = state["results"]["hypotheses"]["verified"][: config.MAX_SCENARIOS]
    if not scenarios:
        return "qualification"
    common = {k: state[k] for k in ("case_path", "run_dir", "budget")}
    return [Send("enquete", {**common, "scenario": sc}) for sc in scenarios]


# --- qualification et rédaction ------------------------------------------------------------------


def retained(state: State) -> list[dict[str, Any]]:
    return sorted(
        (e for e in state.get("enquetes", []) if e["verdict"] in RETAINED), key=lambda e: e["scenario"]["n"]
    )


def _enquete_lines(e: dict[str, Any]) -> list[str]:
    sc = e["scenario"]
    lines = [f"--- {scenario_block(sc)}", f"Verdict du contradicteur : {e['verdict']}"]
    lines += [f"[{f['sens'].upper()}] {finding_line(f)}" for f in e["instruction"]["verified"]]
    lines += [f"[OBJECTION] {finding_line(f)}" for f in e["contradiction"]["verified"]]
    return lines


async def node_qualification(state: State) -> dict:
    kept = retained(state)
    if not kept:
        return {
            "results": {"qualification": empty("Aucun scénario retenu : aucune qualification envisagée.")}
        }
    run_dir = state["run_dir"]
    budget = Budget(**state["budget"])
    extraction = load_extraction(run_dir)
    index = evidence_index(extraction)
    cat = prompts.catalog()
    ids = [q["id"] for q in cat["qualifications"]]
    catalog_text = "\n".join(
        f"- {q['id']} — {q['intitule']} ({q['base']}) : éléments : " + " ; ".join(q["elements"])
        for q in cat["qualifications"]
    )
    room = budget.chunk_chars(prompts.QUALIFICATION["max_tokens"], overhead(prompts.QUALIFICATION) + len(catalog_text), whole_context=True)  # fmt: skip
    lines, notes = _block([line for e in kept for line in _enquete_lines(e)], room // 2, "constats d'enquête")
    cited = [f["evidence"] for e in kept for f in [e["scenario"], *e["instruction"]["verified"]]]
    evidence, allowed = cited_chronology(index, cited, max(2000, room - sum(map(len, lines))))
    user = (
        f"=== CATALOGUE DES QUALIFICATIONS ({cat['droit']}) ===\n{catalog_text}\n\n"
        f"=== SCÉNARIOS RETENUS ET LEUR INSTRUCTION ===\n" + "\n".join(lines) + "\n\n"
        f"=== PREUVES (UTC) ===\n{evidence}\n\n"
        f"{prompts.INTEGRITY_RULE}\n\n{prompts.QUALIFICATION['task']}\n\n{prompts.OUTPUT_RULES}"
    )
    numbers = {e["scenario"]["n"] for e in kept}

    def check(f: dict[str, Any]) -> str | None:
        if not isinstance(f.get("scenario"), int) or f["scenario"] not in numbers:
            return f"numéro de scénario inconnu : {f.get('scenario')!r}"
        if f.get("qualification") not in ids:
            return f"qualification hors catalogue : {f.get('qualification')!r}"
        return None

    result, problems = await run_agent(
        "qualification", prompts.QUALIFICATION["system"], user, prompts.QUALIFICATION["max_tokens"], index,
        allowed, run_dir, prompts.qualification_format(ids), check=check,
    )  # fmt: skip
    # un élément examiné mais non établi n'est pas un élément soutenu : il reste dans findings.json
    result["non_etablis"] = [f for f in result["verified"] if f.get("etat") != "etabli"]
    result["verified"] = [f for f in result["verified"] if f.get("etat") == "etabli"]
    supported = {(f["scenario"], f["qualification"]) for f in result["verified"]}
    # un élément manquant n'est rendu que s'il recopie un élément constitutif du catalogue
    elements = {q["id"]: {_norm(x): x for x in q["elements"]} for q in cat["qualifications"]}
    raw = result["extra"].get("manquants")
    result["manquants"] = [
        {**m, "element": elements[m["qualification"]][_norm(m["element"])]}
        for m in (raw if isinstance(raw, list) else [])
        if isinstance(m, dict)
        and isinstance(m.get("scenario"), int)
        and isinstance(m.get("qualification"), str)
        and isinstance(m.get("element"), str)
        and (m["scenario"], m["qualification"]) in supported
        and _norm(m["element"]) in elements.get(m["qualification"], {})
        # ni s'il est à la fois soutenu et dit manquant (« Élément « … » : » ouvre chaque constat)
        and not any(
            f["scenario"] == m["scenario"]
            and f["qualification"] == m["qualification"]
            and f"« {_norm(m['element'])} »" in _norm(f["claim"])
            for f in result["verified"]
        )
    ]
    return {"results": {"qualification": result}, "errors": notes + problems}


async def node_redaction(state: State) -> dict:
    run_dir = state["run_dir"]
    budget = Budget(**state["budget"])
    extraction = load_extraction(run_dir)
    index = evidence_index(extraction)
    results = state.get("results", {})
    kept = retained(state)
    _, context = signals(results, index)
    room = budget.chunk_chars(
        prompts.REDACTION["max_tokens"], overhead(prompts.REDACTION), whole_context=True
    )
    ctx, notes = _block([signal_line(f) for f in context], room // 6, "constats de contexte")
    enq, notes2 = _block([line for e in kept for line in _enquete_lines(e)], room // 3, "constats d'enquête")
    qual = [
        f"- scénario {f['scenario']} : {f['qualification']} — {finding_line(f)}"
        for f in results.get("qualification", {}).get("verified", [])
    ]
    qual, notes3 = _block(qual, room // 8, "éléments de qualification")
    cited = [
        f["evidence"]
        for e in kept
        for f in [e["scenario"], *e["instruction"]["verified"], *e["contradiction"]["verified"]]
    ] + [f["evidence"] for f in context if signal_line(f) in set(ctx)]
    used = sum(map(len, ctx + enq + qual))
    evidence, allowed = cited_chronology(index, cited, max(2000, room - used))
    if not allowed:  # rien de vérifié à rapporter : pas d'appel, donc pas d'invention
        return {"results": {"redaction": empty("Aucun constat vérifié : aucun appel au modèle.")}}
    user = (
        f"=== CONTEXTE (terminal, utilisateur, relations) ===\n{chr(10).join(ctx) or '(aucun constat)'}\n\n"
        f"=== SCÉNARIOS RETENUS ===\n{chr(10).join(enq) or '(aucun scénario retenu)'}\n\n"
        f"=== QUALIFICATIONS ENVISAGÉES ===\n{chr(10).join(qual) or '(aucune)'}\n\n"
        f"=== PREUVES (UTC) ===\n{evidence}\n\n"
        f"{prompts.INTEGRITY_RULE}\n\n{prompts.REDACTION['task']}\n\n{prompts.OUTPUT_RULES}"
    )
    numbers = {e["scenario"]["n"] for e in kept}

    def check(f: dict[str, Any]) -> str | None:
        if f.get("section") not in ("synthese", "recit", "acte"):
            return "section inconnue"
        if f["section"] == "acte" and not numbers:
            return "aucun scénario retenu : aucun acte d'enquête à proposer"
        if f["section"] == "recit" and (
            not isinstance(f.get("scenario"), int) or f["scenario"] not in numbers
        ):
            return f"récit d'un scénario non retenu : {f.get('scenario')!r}"
        return None

    result, problems = await run_agent(
        "redaction", prompts.REDACTION["system"], user, prompts.REDACTION["max_tokens"], index, allowed,
        run_dir, prompts.REDACTION_FORMAT, check=check,
    )  # fmt: skip
    if not any(f["section"] == "synthese" for f in result["verified"]):  # le modèle l'omet parfois
        again, more = await run_agent(
            "redaction.synthese", prompts.REDACTION["system"], f"{user}\n\n{prompts.SYNTHESIS_ONLY}",
            prompts.REDACTION["max_tokens"], index, allowed, run_dir, prompts.REDACTION_FORMAT,
            check=lambda f: None if f.get("section") == "synthese" else "seule la section synthese est attendue",
        )  # fmt: skip
        result, problems = merge([result, again]), problems + more
    return {"results": {"redaction": result}, "errors": notes + notes2 + notes3 + problems}


# --- extraction et rapport -----------------------------------------------------------------------


async def node_extract(state: State) -> dict:
    case = Path(state["case_path"]).resolve()
    run_dir = Path(state.get("run_dir") or new_run_dir(case))
    if run_dir.resolve().is_relative_to(case):
        raise ValueError(f"le dossier d'exécution ne peut pas être dans le dossier de preuves : {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)
    if any(not p.name.startswith("checkpoint.") for p in run_dir.iterdir()):
        raise FileExistsError(
            f"dossier d'exécution déjà utilisé : {run_dir} (une exécution ne se réécrit pas)"
        )
    started = await asyncio.to_thread(manifest.start, case)  # empreinte des preuves avant toute lecture
    (run_dir / "manifest.json").write_text(
        json.dumps(started, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    async with open_case(case) as cs:
        extraction = await extract_case(cs, state.get("since"), state.get("until"))
        (run_dir / "tool_calls.jsonl").write_text(
            "".join(json.dumps(c, ensure_ascii=False) + "\n" for c in cs.journal), encoding="utf-8"
        )
    save_extraction(str(run_dir), extraction)
    # ce que le serveur vient de lire est-il bien ce qui a été empreinté avant la lecture ?
    started, moved = await asyncio.to_thread(manifest.check_evidence, started, case, "après extraction")
    (run_dir / "manifest.json").write_text(
        json.dumps(started, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    sample = "\n".join(record_line(r) for e in extraction["sources"].values() for r in e["records"][:40])
    budget = await measure(sample)
    (run_dir / "budget.json").write_text(json.dumps(budget.as_dict()), encoding="utf-8")
    errors = [
        f"extraction « {e['label']} » : {e['error']}"
        for e in extraction["sources"].values()
        if e["status"] == "error"
    ]
    errors += moved
    if not any(e["records"] for e in extraction["sources"].values()):
        errors.append(
            "aucun des artefacts attendus n'est présent dans ce dossier : est-ce bien une sortie iLEAPP ?"
        )
    if not budget.measured:
        errors.append(
            "budget de contexte non mesuré sur le serveur d'inférence : valeurs par défaut prudentes"
        )
    for err in errors:
        logger.error(err)
    return {"run_dir": str(run_dir), "budget": budget.as_dict(), "errors": errors}


def draft_report(state: State, errors: list[str], man: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """(rapport principal, contenu de preuves.json)."""
    return render(
        Path(state["case_path"]).name,
        load_extraction(state["run_dir"]),
        state.get("results", {}),
        state.get("enquetes", []),
        errors,
        {
            "run": Path(state["run_dir"]).name,
            "manifest": man,
            "review": state.get("review"),
            "cached": sum(
                bool(c.get("cached"))
                for r in [
                    *state.get("results", {}).values(),
                    *(e[k] for e in state.get("enquetes", []) for k in ("instruction", "contradiction")),
                ]
                for c in r.get("calls", [])
            ),
        },
    )


def findings_file(state: State) -> str:
    """Tout ce que les agents ont produit, vérifié ou rejeté : le détail derrière le rapport."""
    data = {"results": state.get("results", {}), "enquetes": state.get("enquetes", [])}
    return json.dumps(data, ensure_ascii=False, indent=1) + "\n"


async def node_report(state: State) -> dict:
    """Revérifie les preuves et le code, puis écrit le rapport. La clôture du dossier revient à la CLI."""
    run_dir = Path(state["run_dir"])
    man = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    man, problems = await asyncio.to_thread(manifest.check_evidence, man, Path(state["case_path"]), "fin")
    man, code_problems = await asyncio.to_thread(manifest.check_code, man)
    problems += code_problems
    man["review"] = state.get("review")
    report, proofs = draft_report(state, state.get("errors", []) + problems, man)
    (run_dir / "findings.json").write_text(findings_file(state), encoding="utf-8")
    (run_dir / "report.md").write_text(report, encoding="utf-8")
    (run_dir / "preuves.json").write_text(evidence_file(proofs), encoding="utf-8")
    (run_dir / "manifest.json").write_text(json.dumps(man, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"final_report": report, "errors": problems}


def new_run_dir(case: Path) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return config.RUNS_DIR / case.name / stamp


def build_graph() -> StateGraph:
    g = StateGraph(State)
    g.add_node("extract", node_extract)
    for domain in DOMAINS:
        g.add_node(domain, node_terminal if domain == "terminal" else make_reader(domain))
        g.add_edge("extract", domain)
        g.add_edge(domain, "hypotheses")
    g.add_node("hypotheses", node_hypotheses)
    g.add_node("enquete", build_enquete().compile())
    g.add_node("qualification", node_qualification)
    g.add_node("redaction", node_redaction)
    g.add_node("report", node_report)
    g.add_edge(START, "extract")
    g.add_conditional_edges("hypotheses", route_scenarios, ["enquete", "qualification"])
    g.add_edge("enquete", "qualification")
    g.add_edge("qualification", "redaction")
    g.add_edge("redaction", "report")
    g.add_edge("report", END)
    return g


graph = build_graph().compile()
