"""Ligne de commande.

python -m forensic_harness <dossier iLEAPP>                 # analyse, puis s'arrête pour validation
python -m forensic_harness --resume <exécution> --approve --analyst "Nom"
python -m forensic_harness --resume <exécution> --reject --note "motif"
python -m forensic_harness <dossier iLEAPP> --no-review     # sans arrêt (évaluation, essais)
python -m forensic_harness <dossier iLEAPP> --plan          # coût prévu, sans appeler le modèle
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

from forensic_harness import config, manifest, prompts
from forensic_harness.budget import measure
from forensic_harness.extract import MODEL_DOMAINS, _extractions, extract_case, parse_window, record_line
from forensic_harness.graph import build_graph, draft_report, findings_file, new_run_dir, reading_prompts
from forensic_harness.mcp import open_case
from forensic_harness.report import evidence_file

logger = logging.getLogger(__name__)
CHECKPOINT = "checkpoint.sqlite"
THREAD = {"configurable": {"thread_id": "run"}}
AWAITING_REVIEW = 3  # code de sortie : analyse faite, rapport en attente de la décision de l'analyste


def _sha256(path: Path) -> str:
    return manifest.sha256_file(path)


def _finish(run_dir: Path, state: dict, started: float, handler: object | None) -> int:
    """Écrit le résumé d'exécution, fige le dossier et rend le code de sortie."""
    errors = state.get("errors", [])
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "case": state["case_path"],
                "seconds": round(time.monotonic() - started, 1),
                "errors": errors,
                "langfuse_trace_id": getattr(handler, "last_trace_id", None),
            },
            ensure_ascii=False,
            indent=1,
        ),
        encoding="utf-8",
    )
    man = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    digest = manifest.seal(run_dir, man)
    print(f"Rapport : {run_dir / 'report.md'}  ({time.monotonic() - started:.0f} s)")
    print(f"Empreinte du manifeste, à consigner hors de cette machine : {digest}")
    for e in errors:
        print(f"ANOMALIE : {e}", file=sys.stderr)
    return 2 if errors else 0


async def run(
    case_path: str, since: str | None = None, until: str | None = None, review: bool = False
) -> tuple[Path, int]:
    """Exécute le graphe sur un cas. Renvoie (dossier d'exécution, code de sortie).

    Avec `review`, l'exécution s'arrête avant le rapport : un brouillon est écrit et la décision de
    l'analyste est attendue (`resume`). Code 2 : anomalies relevées ; 3 : en attente de validation.
    """
    case = Path(case_path).resolve()
    parse_window(since, until)  # une fenêtre illisible est refusée avant de créer quoi que ce soit
    run_dir = new_run_dir(case)
    if run_dir.resolve().is_relative_to(case):
        raise ValueError(f"le dossier d'exécution ne peut pas être dans le dossier de preuves : {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=False)
    run_config: dict = {
        **THREAD,
        "run_name": f"investigation {case.name}",
        "metadata": {"case": case.name, "run_dir": str(run_dir)},
    }
    langfuse = handler = None
    if os.getenv("LANGFUSE_PUBLIC_KEY") and os.getenv("LANGFUSE_SECRET_KEY"):
        from langfuse import get_client
        from langfuse.langchain import CallbackHandler

        langfuse, handler = get_client(), CallbackHandler()
        run_config["callbacks"] = [handler]

    started = time.monotonic()
    async with AsyncSqliteSaver.from_conn_string(str(run_dir / CHECKPOINT)) as saver:
        app = build_graph().compile(checkpointer=saver, interrupt_before=["report"] if review else [])
        state = await app.ainvoke(
            {"case_path": str(case), "run_dir": str(run_dir), "since": since, "until": until},
            config=run_config,
        )
    if langfuse:
        langfuse.flush()
    if review:
        draft = run_dir / "report.draft.md"
        text, proofs = _draft(run_dir, state)
        draft.write_text(text, encoding="utf-8")
        (run_dir / "preuves.json").write_text(evidence_file(proofs), encoding="utf-8")
        (run_dir / "findings.json").write_text(findings_file(state), encoding="utf-8")
        digest = _sha256(draft)
        print(
            f"Analyse terminée, en attente de validation. Brouillon à relire : {draft}\n"
            f"Preuves citées par le brouillon : {run_dir / 'preuves.json'}\n"
            f"Empreinte du brouillon : {digest}\n"
            f'Puis : python -m forensic_harness --resume {run_dir} --draft-sha256 {digest[:16]} --approve --analyst "Nom"\n'
            f'  ou : python -m forensic_harness --resume {run_dir} --draft-sha256 {digest[:16]} --reject --note "motif"'
        )
        return run_dir, AWAITING_REVIEW
    return run_dir, _finish(run_dir, state, started, handler)


def _draft(run_dir: Path, state: dict) -> tuple[str, dict]:
    man = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    return draft_report(state, state.get("errors", []), man)


async def resume(run_dir: Path, status: str, analyst: str | None, note: str | None, draft_sha256: str) -> int:
    """Reprend une exécution arrêtée pour validation et produit le rapport final, décision consignée.

    La décision porte sur un brouillon précis : `draft_sha256` est l'empreinte (au moins 12
    caractères) de celui que l'analyste a lu. La reprise est refusée si le brouillon sur disque
    n'a pas cette empreinte, ou si l'état enregistré (constats, preuves, manifeste) ne redonne
    plus ce brouillon : le rapport final dit la même chose que ce qui a été relu.
    """
    started = time.monotonic()
    if not (run_dir / CHECKPOINT).is_file():
        raise FileNotFoundError(f"aucun point de reprise dans {run_dir}")
    if (run_dir / "manifest.sha256").exists():
        raise ValueError(f"{run_dir} n'attend pas de validation (exécution déjà clôturée)")
    _extractions.pop(str(run_dir), None)  # la reprise relit les preuves extraites sur le disque
    if len(draft_sha256) < 12:
        raise ValueError("--draft-sha256 : au moins 12 caractères de l'empreinte du brouillon relu")
    async with AsyncSqliteSaver.from_conn_string(str(run_dir / CHECKPOINT)) as saver:
        app = build_graph().compile(checkpointer=saver, interrupt_before=["report"])
        snapshot = await app.aget_state(THREAD)
        if "report" not in snapshot.next:
            raise ValueError(
                f"{run_dir} n'attend pas de validation (exécution déjà terminée ou jamais arrêtée)"
            )
        on_disk = _sha256(run_dir / "report.draft.md")
        if not on_disk.startswith(draft_sha256.lower()):
            raise ValueError(
                "le brouillon sur disque n'est pas celui dont l'empreinte est donnée : décision refusée"
            )
        text, proofs = _draft(run_dir, snapshot.values)
        regenerated = hashlib.sha256(text.encode("utf-8")).hexdigest()
        proofs_file, findings = run_dir / "preuves.json", run_dir / "findings.json"
        unchanged = (
            regenerated == on_disk
            and proofs_file.is_file()
            and proofs_file.read_text(encoding="utf-8") == evidence_file(proofs)
            and findings.is_file()
            and findings.read_text(encoding="utf-8") == findings_file(snapshot.values)
        )
        if not unchanged:
            raise ValueError(
                "l'état enregistré ne redonne plus le brouillon relu, ses preuves ou ses constats (brouillon, "
                "preuves.json, findings.json, point de reprise, preuves extraites ou "
                "manifeste modifiés depuis l'arrêt) : décision refusée, relancer l'analyse"
            )
        review = {
            "status": status,
            "analyst": analyst,
            "note": note,
            "at": datetime.now(UTC).isoformat(timespec="seconds"),
            "draft_sha256": on_disk,
        }
        await app.aupdate_state(THREAD, {"review": review})
        state = await app.ainvoke(None, config=THREAD)
    return _finish(run_dir, state, started, None)


async def plan(case_path: str, since: str | None, until: str | None) -> str:
    """Ce qu'une exécution coûterait, sans appeler le modèle : preuves, lots et tokens par domaine."""
    async with open_case(case_path) as cs:
        extraction = await extract_case(cs, since, until)
    sample = "\n".join(record_line(r) for e in extraction["sources"].values() for r in e["records"][:40])
    budget = await measure(sample)
    rows = [
        f"Contexte par slot : {budget.n_ctx} tokens ; {budget.chars_per_token:.2f} caractères par token "
        f"({'mesuré' if budget.measured else 'NON MESURÉ, valeurs par défaut'}) ; lots de {config.CHUNK_TOKENS} tokens.",
        "",
        "| Lecture | Preuves | Lots (appels) | Tokens de prompt (est.) | Tokens de réponse (max) |",
        "| :--- | ---: | ---: | ---: | ---: |",
    ]
    calls = prompt_tokens = answer_tokens = 0
    for domain in MODEL_DOMAINS:
        batches = reading_prompts(domain, extraction, budget)
        tokens = int(sum(len(u) for _, u, _ in batches) / budget.chars_per_token)
        out = len(batches) * prompts.READING[domain]["max_tokens"]
        n = sum(len(tags) for _, _, tags in batches)
        rows.append(f"| {domain} | {n} | {len(batches)} | {tokens} | {out} |")
        calls, prompt_tokens, answer_tokens = (
            calls + len(batches),
            prompt_tokens + tokens,
            answer_tokens + out,
        )
    per_scenario = (
        config.INSTRUCTION_ROUNDS * 800
        + prompts.INSTRUCTION["max_tokens"]
        + prompts.CONTRADICTION["max_tokens"]
    ) * (1 + config.COUNTER_ROUNDS)
    tail = (
        prompts.HYPOTHESES["max_tokens"] + config.MAX_SCENARIOS * per_scenario
        + prompts.QUALIFICATION["max_tokens"] + prompts.REDACTION["max_tokens"]
    )  # fmt: skip
    tail_calls = 3 + config.MAX_SCENARIOS * (config.INSTRUCTION_ROUNDS + 2) * (1 + config.COUNTER_ROUNDS)
    rows += [
        f"| enquête ({config.MAX_SCENARIOS} scénarios au plus), qualification, rédaction | — | ≤ {tail_calls} | — | ≤ {tail} |",
        "",
        f"Total : au moins {calls + 1} appels au modèle (sans scénario), jusqu'à {calls + tail_calls} ; environ "
        f"{prompt_tokens} tokens à lire pour la lecture et jusqu'à {answer_tokens + tail} tokens à écrire "
        "(hors relances et condensations).",
    ]
    return "\n".join(rows)


def main() -> None:
    parser = argparse.ArgumentParser(prog="forensic_harness", description=__doc__.split("\n")[0])
    parser.add_argument("case", nargs="?", default=config.DEFAULT_CASE, help="dossier de sortie iLEAPP")
    parser.add_argument("--since", help="n'analyser que les preuves datées à partir de cette date (ISO)")
    parser.add_argument("--until", help="n'analyser que les preuves datées jusqu'à cette date (ISO)")
    parser.add_argument(
        "--plan", action="store_true", help="coût prévu (lots, tokens), sans appeler le modèle"
    )
    parser.add_argument(
        "--no-review", action="store_true", help="ne pas s'arrêter pour la validation humaine"
    )
    parser.add_argument("--resume", type=Path, metavar="EXÉCUTION", help="reprendre une exécution en attente")
    parser.add_argument(
        "--draft-sha256", metavar="EMPREINTE", help="avec --resume : empreinte du brouillon relu"
    )
    decision = parser.add_mutually_exclusive_group()
    decision.add_argument("--approve", action="store_true", help="avec --resume : valider le brouillon")
    decision.add_argument("--reject", action="store_true", help="avec --resume : rejeter le brouillon")
    parser.add_argument("--analyst", help="nom de l'analyste qui décide")
    parser.add_argument("--note", help="commentaire ou motif de la décision")
    parser.add_argument("--verify", type=Path, metavar="EXÉCUTION", help="contrôler une exécution figée")
    parser.add_argument(
        "--manifest-sha256", metavar="EMPREINTE", help="avec --verify : empreinte notée à la clôture"
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    try:
        if args.verify:
            problems = manifest.verify(args.verify.resolve(), args.manifest_sha256)
            print("\n".join(problems) or "Exécution intacte : livrables et preuves conformes au manifeste.")
            if not args.manifest_sha256:
                print(
                    "(sans --manifest-sha256, un dossier entièrement réécrit avec son manifeste ne se verrait pas)"
                )
            sys.exit(1 if problems else 0)
        if args.resume:
            analyst, note = (args.analyst or "").strip(), (args.note or "").strip()
            if not (args.approve or args.reject) or not args.draft_sha256:
                parser.error("--resume demande --draft-sha256 et une décision : --approve ou --reject")
            if args.approve and not analyst:
                parser.error("--approve demande --analyst : une validation est nominative")
            if args.reject and not note:
                parser.error("--reject demande --note : un rejet se motive")
            status = "approved" if args.approve else "rejected"
            sys.exit(
                asyncio.run(
                    resume(args.resume.resolve(), status, analyst or None, note or None, args.draft_sha256)
                )
            )
        if not args.case:
            parser.error("aucun dossier de cas : passez-le en argument ou définissez CASE_PATH dans .env")
        if args.plan:
            print(asyncio.run(plan(args.case, args.since, args.until)))
            return
        sys.exit(asyncio.run(run(args.case, args.since, args.until, review=not args.no_review))[1])
    except (OSError, ValueError) as e:  # dossier absent, fenêtre illisible, reprise refusée…
        parser.error(str(e))


if __name__ == "__main__":
    main()
