"""Instruction d'un scénario : un sous-graphe par scénario, lancé en parallèle par `Send`.

    instruction ──► contradiction ──(fragile et vérifications demandées)──► instruction ──► …
                         └──────────────────────(sinon)──────────────────────► fin

`instruction` laisse le modèle interroger le dossier avec trois outils en lecture seule, tous servis
par iLEAPP-MCP (recherche, lecture d'un export sur une période, lecture d'un fichier). Chaque ligne
rendue devient une preuve référencée, ajoutée à extraction.json avec sa provenance ; chaque appel
est journalisé dans tool_calls.jsonl. Le modèle rend ensuite ses constats à charge et à décharge,
contrôlés par le code comme les autres. `contradiction` attaque le scénario ; son verdict est
plafonné par le code (pas de scénario « étayé » sans éléments à charge vérifiés).
"""

import json
import operator
import re
from pathlib import Path
from typing import Annotated, Any, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langgraph.graph import END, START, StateGraph

from forensic_harness import config, llm, prompts
from forensic_harness.budget import Budget
from forensic_harness.extract import (
    PROV_FIELDS,
    RAW,
    _record,
    add_records,
    cited_chronology,
    evidence_index,
    evidence_lock,
    in_window,
    load_extraction,
    parse_window,
    record_line,
    save_extraction,
)
from forensic_harness.llm import empty, overhead, run_agent, slot
from forensic_harness.mcp import ToolError, open_case
from forensic_harness.report import finding_line

MAX_TERM = 100  # un terme de recherche, pas un texte
TOOL_CHARS = 8000  # texte rendu au modèle par appel d'outil
FILE_PARTS = 8  # un fichier est transmis en morceaux de MAX_FIELD_CHARS caractères, au plus


class EnqueteState(TypedDict, total=False):
    scenario: dict[str, Any]  # n, titre, claim, evidence, quote, questions
    case_path: str
    run_dir: str
    budget: dict[str, Any]
    round: int
    questions: list[str]
    gathered: list[list[str]]  # références rendues par chaque appel d'outil, tous tours confondus
    instruction: dict[str, Any]
    contradiction: dict[str, Any]
    errors: Annotated[list[str], operator.add]
    enquetes: Annotated[list[dict[str, Any]], operator.add]


class EnqueteOut(TypedDict):
    errors: Annotated[list[str], operator.add]
    enquetes: Annotated[list[dict[str, Any]], operator.add]


def scenario_block(sc: dict[str, Any]) -> str:
    return f"Scénario {sc['n']} — {sc['titre']}\n{finding_line(sc)}"


def _sources(extraction: dict[str, Any]) -> str:
    """Noms exacts des exports du dossier qui contiennent des lignes : ce que `lire_source` accepte."""
    names = {
        e["args"]["artifact_name"]
        for e in extraction["sources"].values()
        if e["tool"] == RAW
        and e["total"]
        and "artifact_name" in e["args"]  # les lectures d'enquête n'en ont pas
    } | {a["name"] for a in extraction["unread"]}
    return " ; ".join(sorted(names))


def _tags(text: Any) -> list[str]:
    return list(dict.fromkeys(re.findall(r"\bE\d+\b", str(text or ""))))


def _bounded(lines: list[str], header: str) -> str:
    out, used = [header], len(header)
    for n, line in enumerate(lines):
        if used + len(line) + 1 > TOOL_CHARS:
            out.append(f"(… {len(lines) - n} lignes de plus non montrées : précise la demande)")
            break
        out.append(line)
        used += len(line) + 1
    return "\n".join(out)


def _ts(item: dict[str, Any]) -> str | None:
    counters = {"truncated_fields": 0}
    return _record(item, counters)["ts"]


async def call_tool(cs, run_dir: str, name: str, args: dict[str, Any]) -> tuple[str, list[str]]:
    """Exécute un outil d'instruction. Renvoie (texte pour le modèle, références des preuves montrées)."""
    extraction = load_extraction(run_dir)
    window = extraction.get("window") or {}
    windowed = bool(window.get("since") or window.get("until"))
    if name == "rechercher":
        term = " ".join(str(args.get("terme", "")).split())[:MAX_TERM]
        if not term:
            return "appel refusé : terme vide", []
        page = await cs.call("global_keyword_search", keyword=term, limit=config.TOOL_ROWS)
        items = [{**h["row_data"], **{k: h.get(k) for k in PROV_FIELDS}} for h in page["items"]]
        items = [i for i in items if in_window(_ts(i), window)]
        key, label, tool, call_args = (
            "enquete_recherches",
            "Enquête : recherches",
            "global_keyword_search",
            {"keyword": term},
        )
        # sous fenêtre, le total brut trahirait des données hors période : on ne le montre pas
        found = f"{page['total_count']} ligne(s) dans le dossier, " if not windowed else ""
        header = f"--- rechercher « {term} » : {found}{len(items)} montrée(s) ---"
    elif name == "lire_source":
        source = str(args.get("source", "")).strip()
        lo, hi = parse_window(args.get("debut"), args.get("fin"))
        items, _, _ = await cs.fetch_all(RAW, artifact_name=source, exact=True)
        period = {"since": lo, "until": hi}
        items = [i for i in items if in_window(_ts(i), window)]
        total = len(items)
        items = [i for i in items if in_window(_ts(i), period)]
        shown = items[: config.TOOL_ROWS]
        more = (
            f", {len(shown)} montrée(s) : précise la période pour voir la suite"
            if len(items) > len(shown)
            else ""
        )
        key, label, tool, call_args = "enquete_sources", "Enquête : lectures d'exports", RAW, {
            "artifact_name": source, "exact": True, "debut": lo, "fin": hi,
        }  # fmt: skip
        header = f"--- lire_source « {source} » {lo or 'début'} → {hi or 'fin'} : {len(items)} ligne(s) sur {total}{more} ---"
        items = shown
    elif name == "lire_fichier":
        if windowed:  # un fichier n'a pas de date fiable : il ne peut pas être rattaché à la période
            return "appel refusé : une fenêtre d'analyse est active et un fichier n'est pas daté", []
        file_name = str(args.get("nom", "")).strip()
        path = str(args.get("chemin") or "").strip() or None
        info = await cs.call(
            "get_file_attachment", file_name=file_name, max_chars=FILE_PARTS * config.MAX_FIELD_CHARS,
            **({"path": path} if path else {}),
        )  # fmt: skip
        text = info.get("text") or ""
        item = {k: info.get(k) for k in PROV_FIELDS}
        item.update(
            {"fichier": info["file_name"], "nature": info["content_kind"], "taille (octets)": info["size_bytes"],
             "sha256": info["sha256"], "note": info.get("note")}
        )  # fmt: skip
        step = config.MAX_FIELD_CHARS
        for n in range(0, len(text), step):
            item[f"texte {n // step + 1}"] = text[n : n + step]
        if info.get("text_chars_total", 0) > len(text):
            item["texte coupé"] = f"{len(text)} caractères montrés sur {info['text_chars_total']}"
        items = [item]
        key, label, tool, call_args = "enquete_fichiers", "Enquête : fichiers lus", "get_file_attachment", {
            "file_name": file_name, "path": path,
        }  # fmt: skip
        header = f"--- lire_fichier « {file_name} » ---"
    else:
        return f"outil inconnu : {name}", []
    async with evidence_lock(run_dir):
        extraction = load_extraction(run_dir)
        recs = add_records(extraction, key, label, tool, call_args, items)
        save_extraction(run_dir, extraction)
    return _bounded([record_line(r) for r in recs], header), [r["tag"] for r in recs]


async def node_instruction(state: EnqueteState) -> dict[str, Any]:
    sc, run_dir = state["scenario"], state["run_dir"]
    budget = Budget(**state["budget"])
    rnd = state.get("round", 0) + 1
    agent = f"instruction.{sc['n']}" + (f".{rnd}" if rnd > 1 else "")
    questions = state.get("questions") or sc.get("questions") or []
    gathered = list(state.get("gathered", []))
    errors: list[str] = []
    room = budget.chunk_chars(
        prompts.INSTRUCTION["max_tokens"], overhead(prompts.INSTRUCTION), whole_context=True
    )

    index = evidence_index(load_extraction(run_dir))
    known, _ = cited_chronology(index, [[t] for t in sc["evidence"]] + gathered, room // 3)
    intro = (
        f"=== SCÉNARIO À INSTRUIRE ===\n{scenario_block(sc)}\n\n"
        f"=== PREUVES DÉJÀ CONNUES (UTC) ===\n{known}\n\n"
        "=== VÉRIFICATIONS DEMANDÉES ===\n" + "\n".join(f"- {q}" for q in questions) + "\n\n"
        f"=== SOURCES DU DOSSIER (noms exacts pour `lire_source`) ===\n{_sources(load_extraction(run_dir))}\n\n"
        f"{prompts.INSTRUCTION['tools']}"
    )
    messages: list[Any] = [SystemMessage(content=prompts.INSTRUCTION["system"]), HumanMessage(content=intro)]
    used = len(intro)
    journal: list[dict] = []
    asked: set[str] = set()
    async with open_case(state["case_path"]) as cs:
        picked: list[str] | None = None
        for _ in range(config.INSTRUCTION_ROUNDS):
            if used > room:
                errors.append(f"{agent} : contexte plein, instruction arrêtée avant le dernier tour d'outils")
                break
            try:
                async with slot():
                    resp = await llm.get_tool_llm(800).ainvoke(messages)
            except Exception as e:
                errors.append(f"{agent} : tour d'outils interrompu ({type(e).__name__} : {e})")
                break
            calls = getattr(resp, "tool_calls", None) or []
            if not calls:
                picked = _tags(resp.content)
                break
            messages.append(resp)
            for n, call in enumerate(calls):  # chaque appel reçoit une réponse, même refusé
                key = json.dumps([call.get("name"), call.get("args")], sort_keys=True, ensure_ascii=False)
                if n >= 3:
                    body = "appel ignoré : trois appels au plus par tour"
                elif key in asked:
                    body = "appel déjà fait : sa réponse est plus haut, demande autre chose"
                else:
                    asked.add(key)
                    try:
                        body, tags = await call_tool(
                            cs, run_dir, call.get("name", ""), call.get("args") or {}
                        )
                        gathered.append(tags)
                    except (ToolError, ValueError) as e:
                        body = f"échec : {e}"
                messages.append(ToolMessage(content=body, tool_call_id=call["id"]))
                used += len(body)
        if picked is None and gathered:  # tours épuisés : l'enquêteur désigne encore ses preuves décisives
            try:
                async with slot():
                    resp = await llm.get_tool_llm(400).ainvoke(
                        [*messages, HumanMessage(content=prompts.INSTRUCTION["pick"])]
                    )
                picked = _tags(resp.content)
            except Exception as e:
                errors.append(f"{agent} : choix des preuves décisives impossible ({type(e).__name__} : {e})")
        journal = cs.journal
    async with evidence_lock(run_dir):
        with open(Path(run_dir) / "tool_calls.jsonl", "a", encoding="utf-8") as f:
            f.write("".join(json.dumps({**c, "agent": agent}, ensure_ascii=False) + "\n" for c in journal))

    index = evidence_index(load_extraction(run_dir))
    # les preuves que l'enquêteur a désignées passent en premier quand tout ne tient pas dans le prompt
    seen = set(sc["evidence"]) | {t for g in gathered for t in g}  # il ne désigne que ce qu'il a vu
    first = [[t] for t in picked or [] if t in seen]
    evidence, shown = cited_chronology(index, first + [[t] for t in sc["evidence"]] + gathered, room)
    user = (
        f"=== SCÉNARIO À INSTRUIRE ===\n{scenario_block(sc)}\n\n"
        "=== VÉRIFICATIONS DEMANDÉES ===\n" + "\n".join(f"- {q}" for q in questions) + "\n\n"
        f"=== PREUVES : CELLES DU SCÉNARIO ET CELLES QUE TU AS LUES (UTC) ===\n{evidence}\n\n"
        f"{prompts.INTEGRITY_RULE}\n\n{prompts.INSTRUCTION['task']}\n\n{prompts.OUTPUT_RULES}"
    )
    result, problems = await run_agent(
        agent, prompts.INSTRUCTION["system"], user, prompts.INSTRUCTION["max_tokens"], index, shown, run_dir,
        prompts.INSTRUCTION_FORMAT,
        check=lambda f: None if f.get("sens") in ("charge", "decharge", "contexte") else "champ « sens » invalide",
    )  # fmt: skip
    result["tools_used"] = len([c for c in journal if c["tool"] != "get_case_info"])
    return {"instruction": result, "gathered": gathered, "round": rnd, "errors": errors + problems}


async def node_contradiction(state: EnqueteState) -> dict[str, Any]:
    sc, run_dir = state["scenario"], state["run_dir"]
    budget = Budget(**state["budget"])
    agent = f"contradiction.{sc['n']}" + (f".{state['round']}" if state.get("round", 1) > 1 else "")
    instr = state["instruction"]
    charge = [f for f in instr["verified"] if f["sens"] == "charge"]
    if not charge:  # rien à contredire : pas d'appel, le scénario n'est pas étayé
        result = {**empty("Aucun élément à charge vérifié : contradicteur non appelé."), "extra": {}}
        return {"contradiction": {**result, "verdict": "non_etaye", "verifier": []}}
    room = budget.chunk_chars(
        prompts.CONTRADICTION["max_tokens"], overhead(prompts.CONTRADICTION), whole_context=True
    )
    lines = [f"[{f['sens'].upper()}] {finding_line(f)}" for f in instr["verified"]]
    cited = [sc["evidence"], *(f["evidence"] for f in charge), *(f["evidence"] for f in instr["verified"])]
    index = evidence_index(load_extraction(run_dir))
    findings_text = "\n".join(lines) or "(aucun constat vérifié)"
    evidence, shown = cited_chronology(index, cited, max(2000, room - len(findings_text)))
    user = (
        f"=== SCÉNARIO ===\n{scenario_block(sc)}\n\n"
        f"=== CONSTATS DE L'INSTRUCTION ===\n{findings_text}\n\n"
        f"=== PREUVES CITÉES (UTC) ===\n{evidence}\n\n"
        f"{prompts.INTEGRITY_RULE}\n\n{prompts.CONTRADICTION['task']}\n\n{prompts.OUTPUT_RULES}"
    )
    result, problems = await run_agent(
        agent, prompts.CONTRADICTION["system"], user, prompts.CONTRADICTION["max_tokens"], index, shown,
        run_dir, prompts.CONTRADICTION_FORMAT,
    )  # fmt: skip
    verdict = result["extra"].get("verdict")
    # le verdict du modèle est plafonné par ce que le code a vérifié
    if verdict not in prompts.VERDICTS:
        problems.append(f"{agent} : verdict absent ou invalide ({verdict!r}), scénario tenu pour fragile")
        verdict = "fragile"
    distinct = {t for f in charge for t in f["evidence"]}
    established = [f for f in charge if f["kind"] != "hypothese"]
    if verdict == "etaye" and (len(charge) < 2 or len(distinct) < 2 or not established):
        verdict = "fragile"
        problems.append(
            f"{agent} : « étayé » ramené à « fragile » (il faut deux éléments à charge vérifiés, "
            "deux preuves distinctes et au moins un fait ou une inférence)"
        )
    result["verdict"] = verdict
    asked = result["extra"].get("verifier")
    result["verifier"] = [q for q in asked if isinstance(q, str)][:3] if isinstance(asked, list) else []
    return {"contradiction": result, "errors": problems}


def after_contradiction(state: EnqueteState) -> str:
    c = state["contradiction"]
    again = c["verdict"] == "fragile" and c["verifier"] and state.get("round", 1) <= config.COUNTER_ROUNDS
    return "again" if again else "done"


def node_again(state: EnqueteState) -> dict[str, Any]:
    return {"questions": state["contradiction"]["verifier"]}


def node_done(state: EnqueteState) -> dict[str, Any]:
    return {
        "enquetes": [
            {
                "scenario": state["scenario"],
                "instruction": state["instruction"],
                "contradiction": state["contradiction"],
                "verdict": state["contradiction"]["verdict"],
                "rounds": state.get("round", 1),
            }
        ]
    }


def build_enquete() -> StateGraph:
    g = StateGraph(EnqueteState, output_schema=EnqueteOut)
    g.add_node("instruction", node_instruction)
    g.add_node("contradiction", node_contradiction)
    g.add_node("reprise", node_again)
    g.add_node("fin", node_done)
    g.add_edge(START, "instruction")
    g.add_edge("instruction", "contradiction")
    g.add_conditional_edges("contradiction", after_contradiction, {"again": "reprise", "done": "fin"})
    g.add_edge("reprise", "instruction")
    g.add_edge("fin", END)
    return g
