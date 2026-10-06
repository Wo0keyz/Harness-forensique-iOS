"""Rapport principal et fichier des preuves : du texte produit par du code à partir des constats vérifiés.

Le rapport ne cite que des références `P<n>`, numérotées dans l'ordre où elles apparaissent.
preuves.json décrit chacune : identifiant de preuve du serveur MCP, export, enregistrement,
fichier iOS d'origine, empreinte, contenu exact vu par le modèle, et l'appel MCP qui la relit.
C'est le seul fichier que l'analyste ouvre pour vérifier le rapport.
"""

import json
import re
from pathlib import PurePosixPath
from typing import Any

from forensic_harness import prompts
from forensic_harness.extract import coverage_table, evidence_index
from forensic_harness.validate import _TAG_LIKE

KIND_LABEL = {"fait": "FAIT", "inference": "INFÉRENCE", "hypothese": "HYPOTHÈSE"}
VERDICT_LABEL = {"etaye": "ÉTAYÉ", "fragile": "À VÉRIFIER", "non_etaye": "NON ÉTAYÉ"}
REVIEW_LABEL = {"approved": "VALIDÉ PAR L'ANALYSTE", "rejected": "REJETÉ PAR L'ANALYSTE"}


def _inline(text: Any) -> str:
    """Texte venu du modèle ou d'une preuve, rendu sur une seule ligne et sans structure Markdown.

    Un constat ne doit pas pouvoir dessiner un titre, un tableau, un lien ou une fausse référence
    dans le rapport, ni dans le prompt des agents suivants. Les adresses sont neutralisées
    (`http[:]//`, `www[.]`) pour ne pas devenir cliquables.
    """
    flat = re.sub(r"\s+", " ", str(text)).strip()
    flat = re.sub(r"([\\|`\[\]<>*#])", r"\\\1", flat)
    flat = re.sub(r"(?i)\b(https?|ftp|mailto|javascript|file):", r"\1[:]", flat)
    return re.sub(r"(?i)\bwww\.", "www[.]", flat)


def finding_line(f: dict[str, Any], refs: dict[str, str] | None = None) -> str:
    """Un constat sur une ligne. Avec `refs`, les références `E…` deviennent les `P…` du rapport."""
    tags = [refs[t] for t in f["evidence"]] if refs is not None else f["evidence"]
    cite = f" [{', '.join(tags)}]" if tags else ""
    quote = f" — « {_inline(f['quote'])} »" if f["quote"] else ""
    claim = f["claim"]
    # une référence E… écrite par le modèle (le contrôle l'exige dans evidence) devient sa P… ; un constat du
    # code n'en écrit pas, ses valeurs recopiées (« E5:8E:… ») restent intactes
    if refs is not None and f.get("source") != "code":
        claim = _TAG_LIKE.sub(lambda m: refs[f"E{m[1]}"] if f"E{m[1]}" in f["evidence"] else m[0], claim)
    return f"- **{KIND_LABEL[f['kind']]}** — {_inline(claim)}{cite}{quote}"


def _file(inference: dict[str, Any]) -> str:
    return str(inference.get("model_file") or "fichier non identifié").rsplit("/", 1)[-1]


def header(meta: dict[str, Any], n_proofs: int) -> str:
    """Bloc d'identification du rapport : exécution, preuves, modèle, validation humaine."""
    man, review = meta.get("manifest") or {}, meta.get("review")
    if review:
        status = (
            f"**{REVIEW_LABEL[review['status']]}** — {_inline(review.get('analyst') or 'analyste non nommé')}, "
            f"{review.get('at')}" + (f" — {_inline(review['note'])}" if review.get("note") else "")
        )
    else:
        status = "**NON RELU PAR UN ANALYSTE** — sortie brute du système, à ne pas utiliser en l'état"
    inference = man.get("inference", {})
    evidence = man.get("evidence", {})
    checks = len(man.get("evidence_checks", []))
    unchanged = {
        True: f"inchangées aux {checks} contrôle(s) faits depuis le début de l'exécution",
        False: "**MODIFIÉES PENDANT L'EXÉCUTION**",
    }.get(man.get("evidence_unchanged"), "non revérifiées")
    model_file = _file(inference)
    harness = str((man.get("code") or {}).get("harness", {}).get("commit"))
    # une reprise depuis un checkpoint garde le manifeste de la lecture : le code du rapport peut différer
    at_report = str((man.get("code_at_report") or {}).get("harness", {}).get("commit") or harness)
    rows = [
        "| | |",
        "| :--- | :--- |",
        f"| Statut | {status} |",
        f"| Exécution | {_inline(meta.get('run', '—'))} (début {man.get('started_at', '—')}) |",
        f"| Dossier analysé | {evidence.get('files', '—')} fichiers (dossier iLEAPP hors `data/` et `media/`), empreinte {evidence.get('tree_sha256', '—')}, {unchanged} |",
        f"| Preuves citées | {n_proofs}, décrites dans `preuves.json` (à côté de ce rapport) |",
        f"| Modèle | {_inline(inference.get('model', '—'))} ({_inline(model_file)}), serveur {_inline(inference.get('build', '—'))}, "
        f"température {man.get('sampling', {}).get('temperature', '—')}, graine {man.get('sampling', {}).get('seed', '—')}"
        + (
            f", {meta['cached']} réponse(s) relue(s) du cache (même requête au même modèle, exécution antérieure)"
            if meta.get("cached")
            else ""
        )
        + " |",
        *(
            [
                f"| Modèle de lecture | {_inline(read.get('model', '—'))} ({_inline(_file(read))}), serveur "
                f"{_inline(read.get('build', '—'))} : lecture des preuves et sa condensation ; le reste par le "
                "modèle ci-dessus |"
            ]
            if (read := inference.get("lecture"))
            else []
        ),  # fmt: skip
        f"| Code | harness {harness[:12]}{f' (rapport : {at_report[:12]})' if at_report != harness else ''}, "
        f"serveur MCP {str((man.get('code') or {}).get('ileapp_mcp', {}).get('commit'))[:12]}, "
        f"prompts et catalogue {str(man.get('prompts_sha256'))[:12]} |",
    ]
    return (
        "\n".join(rows)
        + "\n\nLe détail (versions, arguments du serveur, empreinte de chaque fichier) est dans `manifest.json`."
    )


class _Refs(dict):
    """E<n> → P<n>, attribuées dans l'ordre d'apparition dans le rapport ; mémorise où chacune est citée."""

    def __init__(self) -> None:
        super().__init__()
        self.where: dict[str, list[str]] = {}
        self.section = ""
        self.rendered: list[dict[str, Any]] = []  # chaque constat imprimé dans le rapport

    def __missing__(self, tag: str) -> str:
        self[tag] = f"P{len(self) + 1}"
        return self[tag]

    def lines(self, findings: list[dict[str, Any]]) -> str:
        out = []
        for f in findings:
            self.rendered.append(f)
            for t in f["evidence"]:
                sections = self.where.setdefault(t, [])
                if self.section not in sections:
                    sections.append(self.section)
            out.append(finding_line(f, self))
        return "\n".join(out)


def _redaction(results: dict, section: str, scenario: int | None = None) -> list[dict[str, Any]]:
    return [
        f
        for f in results.get("redaction", {}).get("verified", [])
        if f.get("section") == section and (scenario is None or f.get("scenario") == scenario)
    ]


def _scenario(e: dict[str, Any], results: dict, refs: _Refs, number: str) -> str:
    sc, n = e["scenario"], e["scenario"]["n"]
    # le titre et les questions du modèle ne sont pas des constats vérifiés : ils restent dans findings.json
    title = f"### {number} Scénario {n} — {VERDICT_LABEL[e['verdict']]}"
    refs.section = f"{number} Scénario {n}"
    parts = [title, "*Hypothèse de départ :*\n" + refs.lines([sc])]
    story = _redaction(results, "recit", n)
    parts.append(
        "**Déroulé**\n\n"
        + (
            refs.lines(story)
            or "La rédaction n'a produit aucune phrase vérifiée pour ce scénario : voir les éléments ci-dessous."
        )
    )
    instr = e["instruction"]["verified"]
    charge = [f for f in instr if f["sens"] == "charge"]
    against = [f for f in instr if f["sens"] == "decharge"]
    context = [f for f in instr if f["sens"] == "contexte"]
    parts.append("**Éléments à charge**\n\n" + (refs.lines(charge) or "Aucun élément à charge vérifié."))
    parts.append("**Éléments à décharge**\n\n" + (refs.lines(against) or "Aucun élément à décharge vérifié."))
    # le contradicteur n'a pas de champ « sens » : il lui arrive de confirmer la charge, d'où un titre neutre
    parts.append(
        "**Examen contradictoire**\n\n"
        + (refs.lines(e["contradiction"]["verified"]) or "Aucun constat vérifié du contradicteur.")
    )
    if context:
        parts.append("**Contexte**\n\n" + refs.lines(context))
    parts.append(_qualifications(results, n, refs))
    return "\n\n".join(parts)


def _qualifications(results: dict, n: int, refs: _Refs) -> str:
    qual = results.get("qualification", {})
    found = [f for f in qual.get("verified", []) if f.get("scenario") == n]
    if not found:
        return "**Qualifications envisageables**\n\nAucune qualification du catalogue n'est soutenue par un élément vérifié."
    by_id = {q["id"]: q for q in prompts.catalog()["qualifications"]}
    out = ["**Qualifications envisageables** (à apprécier par le magistrat)"]
    for qid in dict.fromkeys(f["qualification"] for f in found):
        q = by_id.get(qid, {"intitule": qid, "base": "hors catalogue"})
        missing = [
            m["element"]
            for m in qual.get("manquants", [])
            if m["scenario"] == n and m["qualification"] == qid
        ]
        block = f"*{_inline(q['intitule'])}* ({_inline(q['base'])}) — éléments soutenus par les preuves :\n"
        block += refs.lines([f for f in found if f["qualification"] == qid])
        if missing:
            block += "\n\nÉléments non établis : " + " ; ".join(_inline(m) for m in missing)
        out.append(block)
    return "\n\n".join(out)


def render(
    case_name: str,
    extraction: dict[str, Any],
    results: dict[str, dict[str, Any]],
    enquetes: list[dict[str, Any]],
    errors: list[str],
    meta: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    """(rapport principal en Markdown, contenu de preuves.json)."""
    text, proofs, _ = _render(case_name, extraction, results, enquetes, errors, meta)
    return text, proofs


def rendered_findings(
    extraction: dict[str, Any], results: dict[str, dict[str, Any]], enquetes: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Les constats que le rapport principal imprime : ce que l'analyste lit, donc ce qu'on évalue."""
    return _render("", extraction, results, enquetes, [], {})[2]


def _render(
    case_name: str,
    extraction: dict[str, Any],
    results: dict[str, dict[str, Any]],
    enquetes: list[dict[str, Any]],
    errors: list[str],
    meta: dict[str, Any] | None,
) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    meta = meta or {}
    refs = _Refs()
    body: list[str] = []

    refs.section = "1. Synthèse"
    synth = refs.lines(_redaction(results, "synthese"))
    body.append(
        "## 1. Synthèse\n\n" + (synth or "La rédaction n'a produit aucune phrase de synthèse vérifiée.")
    )

    refs.section = "2. Terminal et utilisateur"
    terminal = refs.lines(results.get("terminal", {}).get("verified", []))
    body.append(
        "## 2. Terminal et utilisateur\n\n"
        + (
            "Relevé par le code dans les exports, sans interprétation : chaque ligne recopie les champs des "
            "preuves citées (les mots de passe et codes lus sur le terminal restent dans leur preuve).\n\n"
            + terminal
            if terminal
            else "Aucune propriété de configuration retenue dans les exports du terminal."
        )
    )

    ordered = sorted(enquetes, key=lambda e: e["scenario"]["n"])
    kept = [e for e in ordered if e["verdict"] in ("etaye", "fragile")]
    dropped = [e for e in ordered if e["verdict"] not in ("etaye", "fragile")]
    hyp = results.get("hypotheses", {})
    if kept:
        cat = prompts.catalog()
        intro = (
            "Chaque scénario a été formulé à partir des signaux relevés à la lecture, instruit à charge et à décharge "
            "avec les outils du serveur iLEAPP-MCP, puis attaqué par un agent contradicteur. ÉTAYÉ : les éléments à "
            "charge établissent le déroulé et les objections ne le renversent pas. À VÉRIFIER : plausible, mais une "
            f"explication innocente reste ouverte ou un élément décisif manque. Qualifications : {_inline(cat['statut'])}"
        )
        sections = [_scenario(e, results, refs, f"3.{i}") for i, e in enumerate(kept, start=1)]
        body.append("## 3. Scénarios retenus\n\n" + intro + "\n\n" + "\n\n".join(sections))
    else:
        why = (
            "aucun scénario n'a pu être formulé à partir des preuves vérifiées"
            if not hyp.get("verified")
            else "aucun scénario instruit n'a résisté à l'examen contradictoire"
        )
        body.append(
            "## 3. Scénarios retenus\n\nAucun scénario retenu" + (f" : {_inline(why)}" if why else ".")
        )

    refs.section = "4. Scénarios examinés et non retenus"
    if dropped:
        lines = []
        for e in dropped:
            sc = e["scenario"]
            objection = e["contradiction"]["verified"][:1]
            lines.append(
                f"- Scénario {sc['n']} — non étayé.\n  "
                + refs.lines([sc])
                + (f"\n  {refs.lines(objection)}" if objection else "")
            )
        body.append("## 4. Scénarios examinés et non retenus\n\n" + "\n".join(lines))
    else:
        body.append("## 4. Scénarios examinés et non retenus\n\nAucun.")

    refs.section = "5. Actes d'enquête suggérés"
    acts = refs.lines(_redaction(results, "acte"))
    body.append("## 5. Actes d'enquête suggérés\n\n" + (acts or "Aucun acte suggéré par la rédaction."))

    body.append(_scope(extraction, results, enquetes, errors))
    proofs = _proofs(extraction, refs, meta)
    out = [
        f"# Rapport d'analyse — {_inline(case_name)}",
        header(meta, len(proofs["preuves"])),
        "Rapport produit par un modèle de langage local à partir d'un export iLEAPP lu par le serveur "
        "iLEAPP-MCP. Chaque phrase porte les références `P…` des preuves qui la fondent ; `preuves.json` "
        "décrit chacune (export, enregistrement, fichier iOS d'origine, empreinte, contenu exact, appel MCP "
        "pour la relire). Le contrôle automatique a vérifié que chaque référence existe et que chaque "
        "citation se trouve dans la preuve citée. Il ne vérifie pas le raisonnement : c'est le travail de "
        "l'analyste.",
        *body,
    ]
    return "\n\n".join(out) + "\n", proofs, refs.rendered


def _scope(extraction: dict, results: dict, enquetes: list[dict], errors: list[str]) -> str:
    read = [
        e
        for e in extraction["sources"].values()
        if e["domain"] != "enquete" and e["status"] == "ok" and e["total"]
    ]
    tools = sum(
        len(e["args"].get("calls", [])) for e in extraction["sources"].values() if e["domain"] == "enquete"
    )
    rejected = sum(len(r.get("rejected", [])) for r in results.values()) + sum(
        len(e[k]["rejected"]) for e in enquetes for k in ("instruction", "contradiction")
    )
    unread = extraction["unread"]
    lines = [
        f"- {len(read)} exports lus en entier ({sum(e['sent'] for e in read)} lignes) ; "
        f"{len(unread)} autres exports non lus d'office, accessibles à l'enquête par les outils.",
        f"- {tools} appel(s) d'outils MCP pendant l'enquête (journal : `tool_calls.jsonl`).",
        f"- {rejected} constat(s) du modèle rejeté(s) par le contrôle automatique, absents de ce rapport "
        "(détail : `findings.json`).",
    ]
    anomalies = "\n".join(f"- {_inline(e)}" for e in errors) if errors else "Aucune."
    return (
        "## 6. Portée et limites\n\n"
        + "\n".join(lines)
        + f"\n\n**Anomalies d'exécution**\n\n{anomalies}"
        + "\n\n**Sources lues**\n\n"
        + coverage_table(extraction)
    )


def _reread(r: dict[str, Any]) -> dict[str, Any]:
    """Appel au serveur iLEAPP-MCP qui relit la preuve."""
    if r["row_id"] == "file":
        return {
            "outil": "get_file_attachment",
            "arguments": {"file_name": PurePosixPath(r["source_file"]).name, "path": r["source_file"]},
        }
    if r["source_table"]:
        name = f"{PurePosixPath(r['source_file']).name}:{r['source_table']}"
    else:
        name = PurePosixPath(r["source_file"]).stem
    return {
        "outil": "get_raw_artifact_data",
        "arguments": {"artifact_name": name, "exact": not r["source_table"]},
        "enregistrement": r["row_id"],
    }


def _proofs(extraction: dict, refs: _Refs, meta: dict) -> dict[str, Any]:
    index = evidence_index(extraction)
    proofs = []
    for tag, ref in sorted(refs.items(), key=lambda kv: int(kv[1][1:])):
        r = index[tag]
        proofs.append(
            {
                "ref": ref,
                "evidence_id": r["uid"],
                "source": r["label"],
                "export": r["source_file"],
                "table": r["source_table"],
                "enregistrement": r["row_id"],
                "chemin_ios": r["ios_path"],
                "empreinte_ligne": r.get("digest"),
                "horodatage_utc": r["ts"],
                "contenu": r["fields"],
                "relire": _reread(r),
                "cite_dans": refs.where.get(tag, []),
                "reference_interne": tag,
            }
        )
    return {
        "rapport": "report.md",
        "execution": meta.get("run"),
        "comment_verifier": (
            "Chaque [P n] du rapport renvoie à l'entrée de même `ref`. `contenu` est la ligne exactement telle que le "
            "modèle l'a lue ; `evidence_id` et `empreinte_ligne` sont calculés par le serveur iLEAPP-MCP à partir de "
            "l'export et de l'enregistrement ; `relire` donne l'appel MCP qui renvoie la même ligne ; `chemin_ios` est "
            "le fichier du téléphone d'où iLEAPP l'a tirée."
        ),
        "preuves": proofs,
    }


def evidence_file(proofs: dict[str, Any]) -> str:
    return json.dumps(proofs, ensure_ascii=False, indent=1) + "\n"
