"""Fiche du terminal et signaux d'applications, produits par le code : aucun appel au modèle.

Le modèle relisait la configuration ligne à ligne pour en paraphraser l'essentiel (2 h de calcul sur
Magnet) et oubliait des valeurs (numéro, Apple ID, ordinateur appairé). Ces valeurs se lisent telles
quelles dans les exports : chaque ligne de la fiche recopie des champs d'une ou plusieurs preuves et
les cite. Les applications de catégories sensibles sont nommées par gabarit, en contexte : une messagerie
chiffrée installée ne suffit pas à ouvrir un scénario (cas témoins), elle éclaire ceux que les messages
ouvrent.
"""

import re
from typing import Any

from forensic_harness.extract import _TS_KEY

# exports « propriété = valeur » : seules ces propriétés entrent dans la fiche (casse, espaces et _ ignorés)
PROPERTIES = re.compile(
    r"^(devicename|producttype|productversion|productbuildversion|serialnumber|reportedphonenumber|"
    r"phonenumber|reportedsubscriberidentity|lastknowniccid|imeis?|meid|lastgoodimsi|"
    r"selfregistrationupdateim[es]i|koperatorroaminginfo3gppcurrentoperatorbundleid|"
    r"accountcreationtimestamp|cloudbackupenabled|lastcloudbackupdate|findmyiphoneaddtime|"
    r".*keepmessagesfordays)$"
)
KEY_COLUMNS = ("Property", "Key", "Setting")
VALUE_COLUMNS = ("Property Value", "Value", "Data Value")
# un secret lu sur le terminal (mot de passe, code, jeton) reste dans sa preuve, jamais dans le rapport
SECRET = re.compile(
    r"(?i)pass|pwd|\bpin\b|pin ?code|token|secret|\b(irk|ltk|csrk|otp)\b|cookie|^path$|credential|seed|salt|"
    r"hash|(private|recovery|auth|api|encryption|security) ?(key|code)|session ?id|auth(?!or)|mot de passe"
)
# colonnes techniques sans intérêt pour l'enquêteur (identifiants internes, rendu, versions de format)
NOISE = re.compile(
    r"(?i)^(identifier|uuid|label-id|device (enclosure )?color|name origin|cb_ver|eap_aka|slot id|version|"
    r"device number|tombstoned|last connection time|root folder title|last sync timestamp)$"
)
APP_SOURCES = ("Apps - Installed", "Apps - Itunes Metadata")
MAX_ROWS = 10  # lignes distinctes par source dans la fiche ; le reste est compté
MAX_VALUE = 120

# (catégorie, libellé, identifiants d'application) ; une extension (« …signal.shareextension ») suit son application
APP_CATEGORIES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "canal_discret",
        "messageries chiffrées ou à haute confidentialité",
        re.compile(
            r"^(org\.whispersystems\.signal|chat\.simplex\.app|com\.loki-project\.loki-messenger|"
            r"com\.interactive\.zangi|ch\.threema\.|com\.mywickr\.|org\.briarproject\.|com\.wire\.|"
            r"im\.vector\.|ph\.telegra\.Telegraph|org\.telegram\.|com\.confide\.|keybase\.|"
            r"(ch|com)\.protonmail\.(?!vpn))",
            re.I,
        ),
    ),
    (
        "dissimulation",
        "VPN, navigation anonyme ou coffres-forts de fichiers",
        re.compile(r"vpn|onionbrowser|torbrowser|keepsafe|privatevault|hiddenvault", re.I),
    ),
    (
        "contrepartie",
        "portefeuilles ou plateformes de cryptomonnaie",
        re.compile(
            r"coinbase|binance|exodus|trustwallet|metamask|blockchain|kraken|electrum|bitcoin|ledgerlive",
            re.I,
        ),
    ),
)
_BUNDLE = re.compile(r"[\w.\-]+")


def _squash(name: str) -> str:
    return re.sub(r"[\s_.\-]", "", name).lower()


def _short(value: str) -> str:
    return value if len(value) <= MAX_VALUE else value[:MAX_VALUE] + "…"


def _entry(label: str, text: str, tags: list[str]) -> dict[str, Any]:
    return {"claim": f"{label} : {text}", "kind": "fait", "evidence": tags, "quote": "", "signal": "contexte",
            "source": "code"}  # fmt: skip


def _profile_lines(source: dict[str, Any]) -> list[dict[str, Any]]:
    recs = source["records"]
    key = next((k for k in KEY_COLUMNS if any(k in r["fields"] for r in recs)), None)
    value = next((v for v in VALUE_COLUMNS if any(v in r["fields"] for r in recs)), None)
    if key and value:  # propriété = valeur : une ligne de fiche pour toute la source
        kept = [
            r for r in recs if PROPERTIES.match(_squash(r["fields"].get(key, ""))) and r["fields"].get(value)
        ]
        if not kept:
            return []
        text = " ; ".join(f"{r['fields'][key]}={_short(r['fields'][value])}" for r in kept)
        return [_entry(source["label"], text, [r["tag"] for r in kept])]
    rows: dict[str, list[dict[str, Any]]] = {}  # lignes identiques aux dates près : une seule ligne de fiche
    for r in recs:
        shown = {k: v for k, v in r["fields"].items() if not SECRET.search(k) and not NOISE.match(k)}
        if not shown:
            continue
        same = " ; ".join(f"{k}={v}" for k, v in shown.items() if not _TS_KEY.search(k))
        rows.setdefault(same or " ; ".join(f"{k}={v}" for k, v in shown.items()), []).append(
            {**r, "shown": shown}
        )
    out = []
    for group in list(rows.values())[:MAX_ROWS]:
        text = " ; ".join(f"{k}={_short(v)}" for k, v in group[0]["shown"].items())
        if len(group) > 5:
            text += f" ({len(group)} lignes identiques aux dates près, les 5 premières citées)"
        out.append(_entry(source["label"], text, [r["tag"] for r in group][:5]))
    if len(rows) > MAX_ROWS:
        rest = [r["tag"] for g in list(rows.values())[MAX_ROWS:] for r in g]
        out.append(_entry(source["label"], f"{len(rows) - MAX_ROWS} autres lignes distinctes, non reprises ici"
                          + (" (les 5 premières citées)" if len(rest) > 5 else ""), rest[:5]))  # fmt: skip
    return out


def _app_signals(sources: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    # nom commercial lu dans les métadonnées App Store : la ligne qui le donne est citée aussi
    names = {
        r["fields"]["Bundle ID"]: r
        for r in sources.get("Apps - Itunes Metadata", {}).get("records", [])
        if r["fields"].get("Bundle ID") and r["fields"].get("Item Name")
    }
    apps: dict[str, list[dict[str, Any]]] = {}  # identifiant d'application → toutes les lignes qui le portent
    for r in sources.get("Apps - Installed", {}).get("records", []):
        m = _BUNDLE.match(r["fields"].get("Bundle ID", ""))
        if m:
            apps.setdefault(m.group(), []).append(r)

    def installed(b: str) -> str:
        # « Installed Date » des métadonnées App Store est en UTC ; « Last Installed » (journal d'installation)
        # n'a pas de fuseau et peut être une heure locale (5 h d'écart sur Magnet) : il est dit tel quel
        if b in names and names[b]["fields"].get("Installed Date"):
            return names[b]["fields"]["Installed Date"]
        last = max((r["fields"].get("Last Installed", "") for r in apps[b]), default="")
        return f"{last} (fuseau non précisé par l'export)" if last else "non datée"

    out = []
    for category, label, pattern in APP_CATEGORIES:
        found = sorted(b for b in apps if pattern.search(b))
        roots = [b for b in found if not any(b.startswith(o + ".") for o in found)]
        if not roots:
            continue
        parts = [
            f"{names[b]['fields']['Item Name'] if b in names else b} ({b}, dernière installation {installed(b)})"
            for b in roots
        ]
        tags = [
            t for b in roots for t in [r["tag"] for r in apps[b]] + ([names[b]["tag"]] if b in names else [])
        ]
        out.append(
            {**_entry(f"Applications présentes — {label}", " ; ".join(parts), tags), "category": category}
        )
    return out


def terminal_findings(extraction: dict[str, Any]) -> list[dict[str, Any]]:
    """Fiche du terminal puis signaux d'applications, comme constats vérifiés par construction.

    Chaque constat ne recopie que des champs des preuves qu'il cite, en signal « contexte ».
    """
    sources = {k: e for k, e in extraction["sources"].items() if e["domain"] == "terminal" and e["records"]}
    lines = [line for k, e in sources.items() if k not in APP_SOURCES for line in _profile_lines(e)]
    return lines + _app_signals(sources)
