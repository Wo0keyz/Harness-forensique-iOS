"""Extraction déterministe des preuves via iLEAPP-MCP.

`SOURCES` déclare ce qui est lu, par nom exact d'artefact iLEAPP : pas de recherche floue, donc pas
de lignes étrangères mêlées aux preuves. Tout ce qui existe est lu : rien n'est plafonné ni rogné.
Chaque ligne garde la provenance que le serveur lui a donnée (fichier d'export, numéro
d'enregistrement, fichier iOS d'origine) et reçoit une référence courte `E<n>` que le modèle doit
citer. Les données d'un domaine sont découpées en lots qui tiennent dans le contexte du modèle
(`domain_chunks`), les messages restant groupés par conversation. La lecture est compactée sans rien
retirer de citable : valeurs communes à toute une conversation ou source données une fois, lignes
identiques aux dates près réunies (toutes leurs références restent), identifiants internes omis.
Un artefact absent du dossier n'est pas une erreur ; toute autre panne est consignée, jamais
transformée en liste vide.
"""

import asyncio
import json
import re
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from forensic_harness import config
from forensic_harness.mcp import CaseSession, ToolError

DOMAINS = ("terminal", "communications", "activite")
MODEL_DOMAINS = ("communications", "activite")  # le terminal est relevé par le code (profile.py)
RAW = "get_raw_artifact_data"
PROV_FIELDS = ("evidence_id", "source_file", "source_table", "row_id", "source_ios_path", "row_digest")


@dataclass(frozen=True)
class Source:
    key: str
    domain: str
    label: str
    tool: str
    args: dict[str, Any] = field(default_factory=dict)


def raw(domain: str, label: str, artifact: str) -> Source:
    # exact=True : le serveur ne doit jamais substituer un artefact au nom voisin
    return Source(artifact, domain, label, RAW, {"artifact_name": artifact, "exact": True})


SOURCES: tuple[Source, ...] = (
    # le terminal, son utilisateur, et ce qui a pu être effacé ou caché
    raw("terminal", "Propriétés du terminal", "Device Data"),
    raw("terminal", "Version du système", "System Version plist"),
    raw("terminal", "Ligne et carte SIM", "Subscriber Info"),
    raw("terminal", "IMEI et IMSI", "IMEI - IMSI"),
    raw("terminal", "Cartes SIM", "SIM - UUID"),
    raw("terminal", "Appareils de confiance du compte (modèle, série)", "Trusted Peers"),
    raw("terminal", "Appareils synchronisés iCloud", "Files App - iCloud Sync Device Names"),
    raw("terminal", "Comptes configurés", "Account Data"),
    raw("terminal", "Applications installées", "Apps - Installed"),
    raw("terminal", "Applications (métadonnées App Store)", "Apps - Itunes Metadata"),
    # « Apps - Historical Combined » n'est pas lu d'office : ~80 % de lignes système sans intérêt
    # (déplacements de conteneurs). L'enquête le lit sur une période avec `lire_source`.
    raw("terminal", "Indices d'effacement du terminal", "Wipe Indicators"),
    raw("terminal", "Conservation des messages", "iOS Message Retention"),
    raw("terminal", "Réglages de sauvegarde", "Backup Settings"),
    raw("terminal", "Localiser mon iPhone", "Find My iPhone Settings"),
    raw("terminal", "Réseaux Wi-Fi connus", "WiFi Known Networks Times"),
    raw("terminal", "Bluetooth appairé (LE)", "Bluetooth Paired LE"),
    raw("terminal", "Bluetooth appairé", "Paired Bluetooth Devices"),
    raw("terminal", "Bluetooth appairé (classique)", "Bluetooth Paired"),
    # ce qui est dit, à qui, et par quel canal
    raw("communications", "SMS et iMessage", "SMS"),
    raw("communications", "Appels", "Call History"),
    raw("communications", "Carnet d'adresses", "Address Book"),
    raw("communications", "Courriels Gmail (hors ligne)", "Gmail - Offline Search"),
    raw("communications", "Courriels Apple Mail", "Apple Email"),
    raw("communications", "Interactions entre contacts (CoreDuet)", "InteractionC - Contacts"),
    raw("communications", "Notifications reçues", "Notifications"),
    raw("communications", "Conversations Signal", "Signal - Conversations"),
    raw("communications", "Agenda", "Calendar Events"),
    # ce que l'utilisateur fait : recherches, fichiers, déplacements
    raw("activite", "Fichiers iCloud Drive", "Files App - Files stored in iCloud Drive"),
    raw("activite", "Partages de fichiers (feuille de partage)", "Biome - Share Sheet Feedback"),
    raw("activite", "Fichiers Google Drive", "Google Drive - Items"),
    raw("activite", "Fichiers ouverts en aperçu iCloud", "iCloud Quick Look"),
    raw("activite", "Recherches dans l'App Store", "App Store - Searches"),
    raw("activite", "Historique Safari", "Safari Browser - History"),
    raw("activite", "Recherches Safari", "Safari Browser - Search Terms"),
    raw("activite", "Recherches Safari récentes", "Safari Browser - Recent Web Searches"),
    raw("activite", "Signets Safari", "Safari Browser - Bookmarks"),
    raw("activite", "Onglets Safari", "Safari Browser - Tabs (SafariTabs)"),
    raw("activite", "Navigations Safari (Biome)", "Biome - Safari Navigations"),
    raw("activite", "Commandes et intentions (Siri, raccourcis)", "Biome - App Intents Transcript"),
    raw("activite", "Mots appris par le clavier", "Biome - Keyboard Learned Tokens"),
    raw("activite", "Notes", "Notes"),
    raw("activite", "Rappels", "Reminders"),
    raw("activite", "Lieux significatifs (visites)", "Apple Maps Significant Locations Visits (routined)"),
    raw("activite", "Lieux significatifs", "Apple Maps Significant Locations (routined)"),
    raw("activite", "Trajets Plans", "Apple Maps Trips (routined)"),
    raw("activite", "Verrouillage de l'écran", "knowledgeC - Device Lock Status"),
)

# Artefacts propres à chaque application, découverts par leur nom dans le dossier.
# Les messageries et journaux d'appels sont lus tels qu'iLEAPP les a exportés, colonne par colonne :
# aucune normalisation ne s'interpose entre la ligne d'export et ce que voit le modèle.
DISCOVER: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"^(?!Biome)(?:.* )?Messages(?: \(.+\))?$"), "communications", "Messages"),
    (re.compile(r"^(?!Biome).*Call History(?: - .+)?$"), "communications", "Appels"),
    (re.compile(r"(?: - | )Accounts?$"), "terminal", "Compte d'application"),
    (re.compile(r" - Contacts$|Contacts & Peers$"), "communications", "Contacts d'application"),
)

# colonne qui identifie une conversation dans un export de messagerie (la première présente)
CONVERSATION_COLUMNS = (
    "Conversation With",
    "Chat Name",
    "Chat Contact ID",
    "Conversation ID",
    "Thread ID",
    "Chat ID",
)
_TS_KEY = re.compile(r"time|date|created|modified|install", re.I)
# colonnes de provenance iLEAPP : le serveur les a déjà reportées dans source_ios_path
_PROV_KEY = re.compile(r"^(source (file|path|database)( location)?|file location|full file path)$", re.I)
_EMPTY = (None, "", [], {})


def parse_ts(value: Any) -> str | None:
    """Horodatage en UTC ISO 8601, ou None. iLEAPP exporte en UTC : une valeur sans fuseau est UTC."""
    s = str(value).strip()
    if len(s) < 10:
        return None
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _record(item: dict[str, Any], counters: dict[str, Any]) -> dict[str, Any]:
    prov = item.get("_prov") or {k: item.get(k) for k in PROV_FIELDS}
    if not prov.get("evidence_id") or not prov.get("source_file"):
        raise ToolError("enregistrement renvoyé sans provenance par le serveur MCP")
    fields: dict[str, str] = {}
    ts = None
    for k, v in item.items():
        if v in _EMPTY or k in PROV_FIELDS or str(k).startswith("_") or _PROV_KEY.match(str(k)):
            continue
        if k == "attachment_count" and v == 0:
            continue
        text = ", ".join(map(str, v)) if isinstance(v, list) else str(v)
        if ts is None and _TS_KEY.search(str(k)):
            ts = parse_ts(text)
        if "<truncated " in text:  # coupe faite par le serveur MCP sur un champ très long
            counters["truncated_fields"] += 1
        if len(text) > config.MAX_FIELD_CHARS:
            counters["truncated_fields"] += 1
            text = f"{text[: config.MAX_FIELD_CHARS]}…[coupé : {len(text) - config.MAX_FIELD_CHARS} caractères de plus]"
        fields[str(k)] = text
    return {
        "tag": None,  # attribuée une fois l'extraction terminée
        "uid": prov["evidence_id"],
        "source_file": prov["source_file"],
        "source_table": prov.get("source_table"),
        "row_id": prov.get("row_id"),
        "ios_path": prov.get("source_ios_path"),
        "digest": prov.get("row_digest"),
        "ts": ts,
        "fields": fields,
    }


def parse_window(since: str | None, until: str | None) -> tuple[str | None, str | None]:
    """Fenêtre de dates en UTC ISO. Une date seule en fin de fenêtre désigne le jour entier.

    Une date illisible ou une fenêtre inversée est refusée : l'ignorer analyserait tout le dossier
    en laissant croire qu'il a été filtré.
    """
    since, until = (since or "").strip() or None, (until or "").strip() or None
    lo = parse_ts(since) if since else None
    hi = parse_ts(f"{until}T23:59:59" if until and len(until) == 10 else until) if until else None
    if (since and not lo) or (until and not hi):
        raise ValueError(
            f"fenêtre de dates illisible (format ISO attendu, ex. 2025-12-01) : {since!r} – {until!r}"
        )
    if lo and hi and lo > hi:
        raise ValueError(f"fenêtre de dates inversée : {since} est après {until}")
    return lo, hi


def in_window(ts: str | None, window: dict[str, Any] | None) -> bool:
    """Une preuve sans date lisible est gardée : on ne peut pas dire qu'elle est hors fenêtre."""
    lo, hi = (window or {}).get("since"), (window or {}).get("until")
    return not ts or ((not lo or ts >= lo) and (not hi or ts <= hi))


async def discover_sources(cs: CaseSession) -> tuple[list[Source], list[dict[str, Any]]]:
    """Sources déclarées + artefacts du dossier dont le nom correspond à `DISCOVER`.

    Renvoie aussi l'inventaire des exports du dossier, pour dire ensuite ce qui n'a pas été lu.
    """
    declared = {s.key for s in SOURCES}
    found = list(SOURCES)
    inventory = [a for a in await cs.call("list_available_artifacts") if a["format"] == "tsv"]
    for art in inventory:
        name = art["name"]
        if name in declared:
            continue
        for pattern, domain, label in DISCOVER:
            if pattern.search(name):
                found.append(raw(domain, f"{label} : {name}", name))
                declared.add(name)
                break
    return found, inventory


async def extract_case(cs: CaseSession, since: str | None = None, until: str | None = None) -> dict[str, Any]:
    """Lit toutes les sources, en entier.

    `since` / `until` (dates ISO) restreignent l'analyse aux preuves datées dans la fenêtre ; les
    preuves sans date lisible sont gardées, et ce qui est écarté est compté dans la couverture.
    Renvoie {"sources": {clé: {domain, label, status, total, sent, records, …}}, "unread": [...]}.
    """
    lo, hi = parse_window(since, until)
    sources, inventory = await discover_sources(cs)
    out: dict[str, dict[str, Any]] = {}
    for src in sources:
        entry: dict[str, Any] = {
            "domain": src.domain,
            "label": src.label,
            "tool": src.tool,
            "args": src.args,
            "status": "ok",
            "total": 0,
            "sent": 0,
            "truncated_fields": 0,
            "skipped_empty": 0,
            "out_of_window": 0,
            "error": None,
            "records": [],
        }
        out[src.key] = entry
        try:
            items, total, skipped = await cs.fetch_all(src.tool, **src.args)
            records = [_record(i, entry) for i in items]
        except ToolError as e:
            absent = src.tool == RAW and "not found as a SQLite table or TSV file" in str(e)
            entry.update(status="absent" if absent else "error", error=None if absent else str(e))
            continue
        kept = [r for r in records if in_window(r["ts"], {"since": lo, "until": hi})]
        entry.update(
            total=total,
            sent=len(kept),
            skipped_empty=skipped,
            out_of_window=len(records) - len(kept),
            records=kept,
        )

    # Références courtes, dans l'ordre de lecture : même dossier + même code = mêmes références.
    seen: dict[str, tuple[Any, ...]] = {}
    n = 0
    for entry in out.values():
        for rec in entry["records"]:
            where = (rec["source_file"], rec["source_table"], rec["row_id"])
            if seen.setdefault(rec["uid"], where) != where:
                raise ToolError(
                    f"collision d'identifiant de preuve {rec['uid']} : {seen[rec['uid']]} / {where}"
                )
            n += 1
            rec["tag"] = f"E{n}"

    read_files = {r["source_file"] for e in out.values() for r in e["records"]}
    unread = [
        {"name": a["name"], "rows": a["row_count"]}
        for a in inventory
        if a["file_path"] not in read_files and (a["row_count"] or 0) > 0
    ]
    return {
        "sources": out,
        "unread": sorted(unread, key=lambda a: -(a["rows"] or 0)),
        "window": {"since": lo, "until": hi},
    }


_extractions: dict[str, dict[str, Any]] = {}
_locks: dict[tuple[int, str], asyncio.Lock] = {}


def load_extraction(run_dir: str) -> dict[str, Any]:
    """Preuves de l'exécution, relues depuis le dossier d'exécution (hors de l'état du graphe)."""
    if run_dir not in _extractions:
        _extractions[run_dir] = json.loads((Path(run_dir) / "extraction.json").read_text(encoding="utf-8"))
    return _extractions[run_dir]


def save_extraction(run_dir: str, extraction: dict[str, Any]) -> None:
    (Path(run_dir) / "extraction.json").write_text(
        json.dumps(extraction, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    _extractions[run_dir] = extraction


def evidence_lock(run_dir: str) -> asyncio.Lock:
    """Les branches d'enquête ajoutent des preuves en parallèle : une seule écrit à la fois."""
    key = (id(asyncio.get_running_loop()), run_dir)
    if key not in _locks:
        _locks[key] = asyncio.Lock()
    return _locks[key]


def add_records(
    extraction: dict[str, Any], key: str, label: str, tool: str, args: dict[str, Any], items: list[dict]
) -> list[dict[str, Any]]:
    """Ajoute à l'extraction des lignes lues pendant l'enquête (outil MCP), avec leur provenance.

    Une ligne déjà connue garde sa référence ; une nouvelle reçoit la suivante. Les appels sont
    consignés dans l'entrée `key` (outil, arguments), qui apparaît dans la couverture. Renvoie les
    preuves correspondant à `items`, dans l'ordre. L'appelant sérialise les appels concurrents.
    """
    entry = extraction["sources"].setdefault(
        key,
        {
            "domain": "enquete", "label": label, "tool": tool, "args": {"calls": []}, "status": "ok",
            "total": 0, "sent": 0, "truncated_fields": 0, "skipped_empty": 0, "out_of_window": 0,
            "error": None, "records": [],
        },
    )  # fmt: skip
    entry["args"]["calls"].append({"tool": tool, **args})
    by_uid = {r["uid"]: r for e in extraction["sources"].values() for r in e["records"]}
    count = sum(len(e["records"]) for e in extraction["sources"].values())
    out = []
    for item in items:
        rec = _record(item, entry)
        known = by_uid.get(rec["uid"])
        if known is None:
            count += 1
            rec["tag"] = f"E{count}"
            entry["records"].append(rec)
            by_uid[rec["uid"]] = rec
        out.append(known or rec)
    entry["total"] = entry["sent"] = len(entry["records"])
    return out


# tout ce que str.splitlines() traite comme une fin de ligne
_LINE_BREAKS = re.compile(r"\s*[\r\n\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]+\s*")


def _one_line(value: str) -> str:
    """Un champ ne peut pas ouvrir une nouvelle ligne du prompt : il y fabriquerait une fausse preuve."""
    return _LINE_BREAKS.sub(" ⏎ ", value)


def record_line(rec: dict[str, Any]) -> str:
    return f"[{rec['tag']}] {rec['ts'] or 'sans date'} | {record_text(rec)}"


def record_text(rec: dict[str, Any]) -> str:
    """Texte d'une preuve exactement tel que le modèle le voit (`colonne=valeur ; …`).

    Les citations sont vérifiées contre ce texte : un modèle qui recopie un morceau de la ligne
    affichée, noms de colonnes compris, cite correctement.
    """
    return " ; ".join(f"{_one_line(k)}={_one_line(v)}" for k, v in rec["fields"].items())


def evidence_index(extraction: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Référence → preuve (avec le libellé et le domaine de sa source)."""
    return {
        r["tag"]: {**r, "label": e["label"], "domain": e["domain"]}
        for e in extraction["sources"].values()
        for r in e["records"]
    }


def domain_tags(extraction: dict[str, Any], domain: str) -> set[str]:
    return {r["tag"] for e in extraction["sources"].values() if e["domain"] == domain for r in e["records"]}


def has_data(extraction: dict[str, Any], domain: str) -> bool:
    return bool(domain_tags(extraction, domain))


# identifiants internes d'une ligne : utiles aux jointures, pas à la lecture (l'enquête relit la ligne entière)
_INTERNAL_KEY = re.compile(
    r"(?i)^(row id|message row id|message guid|global message id|message id|entry id|visit id|tab id|tab uuid|"
    r"parent id|server hash)$"
)
MIN_SHARED = 3  # en dessous, une valeur commune n'est pas mise en tête : elle se lit aussi bien sur la ligne


def _compact(recs: list[dict[str, Any]]) -> tuple[str, list[tuple[str, list[str]]]]:
    """(valeurs communes, [(ligne, références)]) pour une conversation ou une source.

    Une colonne de même valeur sur toutes les lignes est dite une fois. Des lignes consécutives identiques
    aux dates près n'en font qu'une, qui porte toutes leurs références et toutes leurs dates ; une ligne à
    plusieurs dates (début, fin…) ou séparée par une autre (une réponse dans une conversation) reste seule.
    """
    shared: dict[str, str] = {}
    if len(recs) >= MIN_SHARED:
        first = recs[0]["fields"]
        shared = {k: v for k, v in first.items() if all(r["fields"].get(k) == v for r in recs)}
    groups: list[tuple[str, list[dict[str, Any]]]] = []
    for r in recs:
        kept = {k: v for k, v in r["fields"].items() if k not in shared and not _INTERNAL_KEY.match(k)}
        same = " ; ".join(f"{_one_line(k)}={_one_line(v)}" for k, v in kept.items() if not _TS_KEY.search(k))
        if sum(bool(_TS_KEY.search(k)) for k in kept) > 1:
            same = r["tag"]  # plusieurs dates : la ligne les garde toutes
        if groups and groups[-1][0] == same:
            groups[-1][1].append({**r, "kept": kept})
        else:
            groups.append((same or r["tag"], [{**r, "kept": kept}]))
    lines = []
    for _, group in groups:
        r = group[0]
        text = " ; ".join(f"{_one_line(k)}={_one_line(v)}" for k, v in r["kept"].items())
        if len(group) == 1:
            lines.append((f"[{r['tag']}] {r['ts'] or 'sans date'} | {text}", [r["tag"]]))
            continue
        dates = [g["ts"] or "sans date" for g in group]
        span = ", ".join(dates)
        same = " ; ".join(
            f"{_one_line(k)}={_one_line(v)}" for k, v in r["kept"].items() if not _TS_KEY.search(k)
        )
        tags = [g["tag"] for g in group]
        lines.append(
            (
                f"{' '.join(f'[{t}]' for t in tags)} {len(group)} lignes identiques aux dates près : {span} | {same}",
                tags,
            )
        )
    head = " ; ".join(f"{_one_line(k)}={_one_line(v)}" for k, v in shared.items())
    return head, lines


def _units(extraction: dict[str, Any], domain: str) -> Iterator[tuple[str, list[tuple[str, list[str]]]]]:
    """(titre, [(ligne, références)]) par source ; les messages sont regroupés par conversation."""
    for e in extraction["sources"].values():
        if e["domain"] != domain or not e["records"]:
            continue
        column = next((c for c in CONVERSATION_COLUMNS if any(c in r["fields"] for r in e["records"])), None)
        conversations: dict[str, list[dict[str, Any]]] = {}
        for r in e["records"]:
            conversations.setdefault(r["fields"].get(column, "?") if column else "", []).append(r)
        for peer, recs in conversations.items():
            head, lines = _compact(recs)
            title = f"{e['label']} — conversation {column}={peer}" if column else e["label"]
            yield title + (f" — commun à toutes les lignes : {head}" if head else ""), lines


def _notes(extraction: dict[str, Any], domain: str) -> str:
    """Ce que le modèle doit savoir sur ce qu'il ne voit pas : sources absentes ou en erreur."""
    entries = [e for e in extraction["sources"].values() if e["domain"] == domain]
    notes = [
        f"=== {e['label']} ===\n(ERREUR D'EXTRACTION : {e['error']} — ne rien conclure sur cette source)"
        for e in entries
        if e["status"] == "error"
    ]
    absent = [e["label"] for e in entries if e["status"] == "absent"]
    if absent:
        notes.append("=== Artefacts absents de ce dossier (rien à en conclure) ===\n" + " ; ".join(absent))
    return "\n\n".join(notes)


def domain_chunks(extraction: dict[str, Any], domain: str, budget: int) -> list[tuple[str, set[str]]]:
    """Découpe les données d'un domaine en lots d'au plus `budget` caractères.

    Renvoie [(texte du lot, références qu'il contient)]. Toutes les preuves du domaine figurent
    dans exactement un lot ; une source ou une conversation trop longue continue au lot suivant.
    """
    notes = _notes(extraction, domain)
    chunks: list[tuple[str, set[str]]] = []
    parts: list[str] = []
    tags: set[str] = set()
    used = len(notes)

    def flush() -> None:
        nonlocal parts, tags, used
        if parts:
            chunks.append(("\n\n".join([*parts, notes] if notes else parts), tags))
        parts, tags, used = [], set(), len(notes)

    for title, units in _units(extraction, domain):
        start = 0
        while start < len(units):
            lines = []
            size = len(title) + 50
            for line, line_tags in units[start:]:
                if used + size + len(line) + 1 > budget and (lines or parts):
                    break
                lines.append(line)
                tags.update(line_tags)
                size += len(line) + 1
            if not lines:  # le lot en cours est plein : on le clôt et on réessaie dans un lot neuf
                flush()
                continue
            head = f"=== {title} — lignes {start + 1} à {start + len(lines)} sur {len(units)} ==="
            parts.append(head + "\n" + "\n".join(lines))
            used += size
            start += len(lines)
    flush()
    return chunks


def _round_robin(groups: list[list[str]]) -> list[str]:
    """Premier élément de chaque groupe, puis le deuxième de chacun, etc., sans doublon."""
    out: dict[str, None] = {}
    for rank in range(max(map(len, groups), default=0)):
        for g in groups:
            if rank < len(g):
                out.setdefault(g[rank])
    return list(out)


def cited_chronology(
    index: dict[str, dict[str, Any]], tags: Iterable[str] | list[list[str]], budget: int
) -> tuple[str, set[str]]:
    """Les preuves citées, dans l'ordre du temps (UTC), bornées au budget.

    `tags` est soit un ensemble de références, soit des groupes classés par importance (les preuves
    d'un constat, les lignes rendues par un appel d'outil…). Quand tout ne tient pas, chaque groupe
    garde ses premières preuves avant qu'un autre n'en ait plus : un constat qui cite cinquante lignes
    ne prive pas les autres des leurs, et la coupe ne frappe pas toujours les preuves les plus récentes.
    Renvoie (texte, références transmises). Une coupe est annoncée en tête du texte.
    """
    tags = list(tags)
    if tags and not isinstance(tags[0], str):
        order = _round_robin([list(g) for g in tags])
    else:
        order = sorted(
            tags, key=lambda t: (index.get(t, {}).get("ts") is None, index.get(t, {}).get("ts") or "")
        )
    order = [t for t in order if t in index]
    kept_tags: set[str] = set()
    used = 0
    for t in order:
        size = len(record_line(index[t])) + len(index[t]["label"]) + 10
        if used + size > budget:
            continue  # une preuve plus courte tient peut-être encore
        used += size
        kept_tags.add(t)
    if not order:
        return "(aucune preuve citée)", kept_tags
    recs = sorted((index[t] for t in kept_tags), key=lambda r: (r["ts"] is None, r["ts"] or ""))
    text = "\n".join(f"{record_line(r)} | source={r['label']}" for r in recs)
    head = (
        ""
        if len(kept_tags) == len(order)
        else f"(PARTIEL : {len(kept_tags)} preuves sur {len(order)} ; les moins citées ne t'ont pas été transmises)\n"
    )
    return head + text, kept_tags


def coverage_table(extraction: dict[str, Any]) -> str:
    rows = [
        "| Source | Outil MCP | État | Lignes transmises / existantes | Sans date | Champs coupés | Fichiers lus |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for e in extraction["sources"].values():
        error = str(e["error"]).replace("|", "\\|").replace("\n", " ")
        state = {"ok": "lue", "absent": "absente du dossier", "error": f"**ERREUR** : {error}"}[e["status"]]
        artifact = e["args"].get("artifact_name")
        tool = f"`{e['tool']}`" + (f" (`{artifact}`)" if artifact else "")
        notes = ""
        if e["out_of_window"]:
            notes += f" ⚠ {e['out_of_window']} hors de la fenêtre de dates"
        if e["skipped_empty"]:
            notes += f" (+{e['skipped_empty']} sans contenu, écartées par le serveur)"
        files = Counter(r["source_file"].rsplit("/", 1)[-1] for r in e["records"])
        rows.append(
            f"| {e['label']} | {tool} | {state} | {e['sent']} / {e['total']}{notes} | "
            f"{sum(1 for r in e['records'] if not r['ts'])} | {e['truncated_fields']} | "
            f"{' ; '.join(f'{name} ({n})' for name, n in files.items()) or '—'} |"
        )
    window = extraction.get("window") or {}
    if window.get("since") or window.get("until"):
        rows.append("")
        rows.append(
            f"Fenêtre de dates demandée : du {window.get('since') or 'début'} au {window.get('until') or 'dernier jour'} "
            "(les preuves sans date lisible sont gardées)."
        )
    return "\n".join(rows)
