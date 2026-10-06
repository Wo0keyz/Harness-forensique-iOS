"""Contrôle automatique des constats du modèle. Aucun modèle ici : du code.

Un constat est accepté seulement si :
- il cite au moins une preuve, quelle que soit sa nature (fait, inférence ou hypothèse) ;
- chaque référence citée existe et faisait partie des preuves transmises à l'agent ;
- sa citation textuelle, s'il en donne une, se retrouve dans une des preuves citées ;
- chaque date et chaque heure (HH:MM) écrite dans le constat figure dans une des preuves citées ;
- l'auteur qu'il déclare pour un message n'est pas contredit par les champs des messages cités
  (expéditeur, sens d'envoi) ;
- il tient en une phrase (pas de texte long où glisser autre chose).

« Vérifié » veut dire exactement cela. Le contrôle ne lit pas le sens de la phrase : il compare
l'auteur déclaré aux preuves, pas le sujet grammatical du texte. Le raisonnement reste à la charge
de l'analyste.
"""

import json
import re
import unicodedata
from typing import Any

from forensic_harness.extract import record_text

KINDS = ("fait", "inference", "hypothese")
# Tout ce qui ressemble à une référence dans le texte d'un constat : « E12 », mais aussi « e12 »,
# « E-12 », « E  12 », « E.12 » et les sosies grec ou cyrillique de la lettre E. Les caractères
# invisibles sont retirés avant la recherche.
_TAG_LIKE = re.compile(r"(?<![A-Za-z0-9])[EeΕЕεе][\W_]{0,3}(\d+)")


# « P12 » est la numérotation du rapport : un constat qui l'écrit fabrique une fausse citation.
_REPORT_REF = re.compile(r"(?<![A-Za-z0-9])[PpРр][\W_]{0,3}\d+")


def _visible(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKC", text) if unicodedata.category(c) != "Cf")


def _tags_in_text(text: str) -> list[str]:
    return list(dict.fromkeys(f"E{n}" for n in _TAG_LIKE.findall(_visible(text))))


MIN_QUOTE = 4  # en dessous, une citation se retrouve partout et ne prouve rien
MAX_CLAIM = 500

_MONTHS_FR = ("janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre",
              "novembre", "décembre")  # fmt: skip
_MONTHS_EN = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
_ISO = re.compile(r"(?<!\d)(\d{4})-(\d{2})-(\d{2})(?!\d)")
_FR_DATE = re.compile(r"(?<!\d)(\d{1,2})(?:er)? (" + "|".join(_MONTHS_FR) + r") (\d{4})(?!\d)", re.I)
_EN_DATE = re.compile(
    r"\b(" + "|".join(_MONTHS_EN) + r")[a-z]*\.? (\d{1,2})(?:st|nd|rd|th)?,? (\d{4})(?!\d)", re.I
)
_EN_DATE2 = re.compile(r"(?<!\d)(\d{1,2}) (" + "|".join(_MONTHS_EN) + r")[a-z]*\.? (\d{4})(?!\d)", re.I)
_SLASH = re.compile(r"(?<!\d)(\d{1,2})[/.](\d{1,2})[/.](\d{4})(?!\d)")
# heure d'un constat : « 20:12 », « 9:05 », « 20h12 » ; « 1h30 » (une durée) n'est pas lu
_CLAIM_CLOCK = re.compile(r"(?<![\d:])(\d{1,2}):(\d{2})(?!\d)|(?<![\d:])(\d{2})h(\d{2})(?!\d)")
_CLOCK = re.compile(r"(?<![\d:])(\d{1,2}):(\d{2})(?::\d{2})?(?:\.\d+)?\s*([ap]\.?m\b)?", re.I)

# champs d'un message qui disent qui l'a écrit, et dans quel sens il est passé
AUTHOR_FIELDS = ("Author", "Sender Name", "Sender Email", "Sender Number", "Sender", "From", "From Address")
DIRECTION_FIELDS = ("Direction", "Message Direction", "From Me", "Is From Me")
_SENT = re.compile(r"(?i)^(outgoing|sent|1|true|yes|signed-in account)$")
_RECEIVED = re.compile(r"(?i)^(incoming|received|0|false|no)$")
# l'utilisateur du terminal, quel que soit le mot employé (« Signed-in account » est la valeur de l'export)
USER = re.compile(r"(?i)\b(utilisat(eur|rice)|propriétaire|signed-in account)\b|^(moi|user|me|owner)$")


def _norm(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).replace("’", "'").replace("“", '"').replace("”", '"')
    return re.sub(r"[\s⏎]+", " ", text).strip().casefold()


def _load(text: str) -> Any:
    """JSON de la réponse. Une réponse coupée en plein milieu garde ses constats complets.

    Le dernier constat, inachevé, est abandonné : on referme la liste après le dernier constat
    entier. L'appelant signale la coupure ; ici on ne fait que ne pas perdre ce qui est lisible.
    """
    try:
        return json.loads(text)
    except ValueError:
        for end in (m.end() for m in reversed(list(re.finditer(r"\}\s*(?=,|\])", text)))):
            try:
                return json.loads(text[:end] + '], "limits": ""}')
            except ValueError:
                continue
        raise


CORE = ("claim", "kind", "evidence", "quote")


def _extra(value: Any) -> Any:
    """Champ propre à un agent (signal, sens, section…) : texte, entier ou liste de textes seulement."""
    if isinstance(value, bool) or not isinstance(value, str | int | list):
        return None
    if isinstance(value, list):
        return [str(v).strip() for v in value if isinstance(v, str | int) and str(v).strip()]
    return value.strip() if isinstance(value, str) else value


def parse_answer(text: str) -> tuple[list[dict[str, Any]], dict[str, Any], str | None]:
    """Réponse JSON du modèle → (constats, champs de premier niveau hors `findings`, erreur de forme ou None).

    Chaque constat garde ses quatre champs communs et les champs propres à l'agent (voir `_extra`) ;
    les champs de premier niveau (`limits`, `verdict`, `manquants`…) sont rendus tels quels.
    """
    try:
        data = _load(text)
        findings = data["findings"]
        assert isinstance(data, dict) and isinstance(findings, list)
        assert all(isinstance(f, dict) for f in findings)
    except (ValueError, KeyError, TypeError, AssertionError):
        return [], {}, "réponse illisible (JSON attendu : {findings: [...], limits: ...})"
    clean = []
    for f in findings:
        item = {
            "claim": str(f.get("claim", "")).strip(),
            "kind": str(f.get("kind", "")),
            "evidence": [str(t) for t in f.get("evidence") or [] if isinstance(t, str)],
            "quote": str(f.get("quote") or "").strip(),
        }
        for k, v in f.items():
            if k not in CORE and (v := _extra(v)) is not None:
                item[str(k)] = v
        if item["claim"]:
            clean.append(item)
    top = {k: v for k, v in data.items() if k != "findings"}
    top["limits"] = str(data.get("limits") or "").strip()
    return clean, top, None


def parse_findings(text: str) -> tuple[list[dict[str, Any]], str, str | None]:
    """Réponse JSON du modèle → (constats, limites, erreur de forme ou None)."""
    findings, top, error = parse_answer(text)
    return findings, top.get("limits", ""), error


def _quoted(quote: str, text: str) -> bool:
    """La citation est-elle dans le texte ? Le modèle réordonne les colonnes (`col=valeur ; col=valeur`)
    et coupe (« … », « ... ») : chaque colonne citée doit se retrouver dans la preuve, ses morceaux coupés
    dans l'ordre. Chaque morceau fait au moins MIN_QUOTE caractères : on ne recolle pas des mots épars."""
    columns = [c for c in (c.strip(" ;,") for c in re.split(r"\s;\s", quote)) if c]
    if not columns:
        return False
    for column in columns:
        parts = [p for p in (p.strip(" ;,") for p in re.split(r"\.\.\.|…", column)) if p]
        if not parts or min(map(len, parts)) < MIN_QUOTE:
            return False
        at = 0
        for part in parts:
            at = text.find(part, at)
            if at < 0:
                return False
            at += len(part)
    return True


def _iso(y: str, m: int, d: str) -> str:
    return f"{y}-{m:02d}-{int(d):02d}"


def _dates(text: str, claim: bool = False) -> set[str]:
    """Dates écrites dans le texte, en ISO. Une preuve s'écrit en ISO ou en anglais (corps de message) ;
    « 12/03/2025 » y est lu dans les deux sens. Un constat s'écrit en ISO ou en français."""
    found = {_iso(y, int(m), d) for y, m, d in _ISO.findall(text)}
    found |= {_iso(y, _MONTHS_FR.index(m.lower()) + 1, d) for d, m, y in _FR_DATE.findall(text)}
    if claim:
        return found | {_iso(y, int(m), d) for d, m, y in _SLASH.findall(text) if 0 < int(m) <= 12}
    found |= {_iso(y, _MONTHS_EN.index(m.lower()) + 1, d) for m, d, y in _EN_DATE.findall(text)}
    found |= {_iso(y, _MONTHS_EN.index(m.lower()) + 1, d) for d, m, y in _EN_DATE2.findall(text)}
    for a, b, y in _SLASH.findall(text):
        found |= {_iso(y, int(m), d) for m, d in ((a, b), (b, a)) if 0 < int(m) <= 12}
    return found


def _clocks(text: str) -> set[str]:
    out = set()
    for h, m, pm in _CLOCK.findall(text):
        hour = int(h) % 12 + (12 if pm.lower().startswith("p") else 0) if pm else int(h)
        out.add(f"{hour:02d}:{m}")
    return out


def _unsupported_moments(claim: str, records: list[dict[str, Any]]) -> list[str]:
    """Dates et heures du constat qu'aucune preuve citée ne porte."""
    text = " ".join(record_text(r) for r in records)
    dates = sorted(_dates(claim, claim=True) - _dates(text))
    said = {f"{int(h or h2):02d}:{m or m2}" for h, m, h2, m2 in _CLAIM_CLOCK.findall(claim)}
    clocks = sorted(said - _clocks(text))
    return dates + clocks


def _squash(text: str) -> str:
    return re.sub(r"\W", "", _norm(text))


def _sender(fields: dict[str, Any]) -> tuple[str | None, str]:
    """(« envoyé », « reçu » ou None, expéditeur écrit dans la ligne) d'un message."""
    author = " ".join(str(fields[k]) for k in AUTHOR_FIELDS if fields.get(k))
    way = None
    for k in DIRECTION_FIELDS:
        value = str(fields.get(k, "")).strip()
        if k == "Direction" and value in ("0", "1"):
            continue  # direction numérique (InteractionC) : sens non documenté, on ne conclut pas
        if _SENT.match(value):
            way = "envoyé"
        elif _RECEIVED.match(value):
            way = "reçu"
    if _SENT.match(author.strip()):
        way, author = "envoyé", ""
    return way, author


def _author_contradiction(author: str, records: dict[str, dict[str, Any]]) -> str | None:
    """Motif de rejet si aucun message cité ne peut être de l'auteur déclaré ; None sinon.

    Seule une contradiction nette rejette : un message reçu attribué à l'utilisateur, ou un auteur
    qui n'est ni l'expéditeur écrit ni compatible avec le sens du message. Une ligne qui ne dit pas
    qui écrit ne contredit rien.
    """
    messages = {t: _sender(r["fields"]) for t, r in records.items()}
    messages = {t: s for t, s in messages.items() if s != (None, "")}
    if not author.strip() or not messages:
        return None
    user, who = bool(USER.search(author.strip())), _squash(author)
    for way, sender in messages.values():
        if user and way != "reçu":
            return None
        named = (
            sender
            and len(who) >= 3
            and (who in _squash(sender) or len(_squash(sender)) >= 3 and _squash(sender) in who)
        )
        # expéditeur écrit dans la ligne (aussi le nom du propriétaire sur un message envoyé) ; sinon le sens suffit
        if not user and (named or not sender and way != "envoyé"):
            return None
    seen = " ; ".join(
        f"{t} : {'envoyé depuis le terminal' if way == 'envoyé' else 'écrit par ' + (sender or 'expéditeur non nommé')}"
        for t, (way, sender) in messages.items()
    )
    return f"auteur « {author} » contredit par les messages cités ({seen})"


def validate(
    findings: list[dict[str, Any]], index: dict[str, dict[str, Any]], allowed: set[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Sépare les constats en (vérifiés, rejetés). Un rejeté porte ses motifs dans `reasons`."""
    verified, rejected = [], []
    for f in findings:
        tags = list(dict.fromkeys(f["evidence"]))
        unknown = [t for t in tags if t not in index]
        unseen = [t for t in tags if t in index and t not in allowed]
        valid = [t for t in tags if t in allowed and t in index]
        reasons = []
        if f["kind"] not in KINDS:
            reasons.append(f"nature de constat inconnue : {f['kind']!r}")
        if len(f["claim"]) > MAX_CLAIM:
            reasons.append(f"constat trop long ({len(f['claim'])} caractères, {MAX_CLAIM} au plus)")
        if unknown:
            reasons.append(f"référence(s) inexistante(s) : {', '.join(unknown)}")
        if unseen:
            reasons.append(f"référence(s) non transmise(s) à cet agent : {', '.join(unseen)}")
        stray = [t for t in _tags_in_text(f["claim"]) if t not in tags]
        if stray:
            reasons.append(
                f"référence(s) dans le texte mais absente(s) du champ evidence : {', '.join(stray)}"
            )
        if _REPORT_REF.search(_visible(f["claim"])):
            reasons.append("référence de rapport (P…) dans le texte : cite les preuves par E… dans evidence")
        if not valid:
            reasons.append("constat sans preuve valide")
        if f["quote"]:
            quote = _norm(f["quote"])
            if len(quote) < MIN_QUOTE:
                reasons.append("citation trop courte pour être vérifiée")
            elif not any(_quoted(quote, _norm(record_text(index[t]))) for t in valid):
                reasons.append("citation introuvable dans les preuves citées")
        if valid:
            moments = _unsupported_moments(f["claim"], [index[t] for t in valid])
            if moments:
                reasons.append(f"date ou heure absente des preuves citées : {', '.join(moments)}")
            contradiction = _author_contradiction(str(f.get("auteur") or ""), {t: index[t] for t in valid})
            if contradiction:
                reasons.append(contradiction)
        if reasons:
            rejected.append({**f, "reasons": reasons})
        else:
            verified.append({**f, "evidence": valid})
    return verified, rejected


def rejection_feedback(rejected: list[dict[str, Any]]) -> str:
    lines = [f"- « {' '.join(f['claim'].split())[:200]} » : {' ; '.join(f['reasons'])}" for f in rejected]
    return (
        "Ta réponse précédente contenait des constats rejetés par le contrôle automatique :\n"
        + "\n".join(lines)
        + "\nRéponds à nouveau avec l'objet JSON complet, en corrigeant ou en retirant ces constats. "
        "N'utilise que des références présentes dans les données."
    )
