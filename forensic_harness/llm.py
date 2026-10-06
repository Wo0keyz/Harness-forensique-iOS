"""Appels au modèle local et contrôle de ses réponses par le code.

Chaque appel est borné par un slot du serveur d'inférence, contraint à un schéma JSON, journalisé
(prompt et réponse bruts dans `llm/`), puis ses constats passent par `validate` avec une relance
en cas de rejet. Une réponse vide, coupée ou en échec n'est jamais silencieuse. Une réponse complète
est gardée dans un cache disque : la même requête au même modèle ne refait pas des heures de lecture.
"""

import asyncio
import functools
import hashlib
import json
import logging
import sqlite3
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from langchain_core.caches import BaseCache
from langchain_core.messages import HumanMessage, SystemMessage, messages_from_dict, messages_to_dict
from langchain_core.outputs import ChatGeneration
from langchain_openai import ChatOpenAI

from forensic_harness import config, prompts
from forensic_harness.validate import parse_answer, rejection_feedback, validate

logger = logging.getLogger(__name__)

_semaphores: dict[tuple[int, bool], asyncio.Semaphore] = {}


class DiskCache(BaseCache):
    """Réponses complètes du modèle, rangées par empreinte de la requête (modèle, paramètres, messages).

    Une reprise, ou une exécution dont seule la fin a changé, relit les réponses déjà obtenues au lieu de
    relancer la lecture. Une réponse vide ou coupée n'est pas gardée : elle sera redemandée.
    """

    # Le serveur est identifié par son modèle (/v1/models) et sa version (/props) : un autre GGUF sous le même
    # nom ne relit pas les réponses de l'ancien. Un cache illisible ou plein ne coûte jamais une réponse :
    # l'appel se fait alors sans lui.

    def __init__(self, path: Path, server: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.server = server
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.db.execute("pragma journal_mode=wal")
        self.db.execute("create table if not exists answers (key text primary key, answer text)")

    def _key(self, prompt: str, llm_string: str) -> str:
        return hashlib.sha256(f"{self.server}\0{llm_string}\0{prompt}".encode()).hexdigest()

    def lookup(self, prompt: str, llm_string: str) -> list[ChatGeneration] | None:
        try:
            row = self.db.execute(
                "select answer from answers where key = ?", (self._key(prompt, llm_string),)
            ).fetchone()
            return row and [ChatGeneration(message=m) for m in messages_from_dict(json.loads(row[0]))]
        except (sqlite3.Error, ValueError, KeyError, TypeError):
            logger.exception("cache des réponses illisible : appel au modèle")
            return None

    def update(self, prompt: str, llm_string: str, return_val: list) -> None:
        if not all(
            g.text.strip() and g.message.response_metadata.get("finish_reason") == "stop" for g in return_val
        ):
            return
        try:
            self.db.execute(
                "insert or replace into answers values (?, ?)",
                (
                    self._key(prompt, llm_string),
                    json.dumps(messages_to_dict([g.message for g in return_val])),
                ),
            )
        except sqlite3.Error:
            logger.exception("cache des réponses non écrit : la réponse est gardée pour cet appel")

    def clear(self, **kwargs: Any) -> None:
        self.db.execute("delete from answers")

    # sur la boucle d'événements, sans fil d'exécution : une requête SQLite prend une milliseconde
    async def alookup(self, prompt: str, llm_string: str) -> list[ChatGeneration] | None:
        return self.lookup(prompt, llm_string)

    async def aupdate(self, prompt: str, llm_string: str, return_val: list) -> None:
        self.update(prompt, llm_string, return_val)


@functools.cache
def _cache(path: str, url: str) -> DiskCache | bool:
    """Cache pour ce serveur, ou False : pas de chemin, serveur muet sur son modèle, base inutilisable."""
    if not path:
        return False
    base = url.removesuffix("/").removesuffix("/v1")
    try:
        # le chemin du modèle vu du conteneur est toujours /models/model.gguf : le GGUF est reconnu à sa taille
        # en octets, ses paramètres, sa quantification et son gabarit de conversation
        with urllib.request.urlopen(base + "/props", timeout=10) as r:
            props = json.load(r)
        with urllib.request.urlopen(base + "/v1/models", timeout=10) as r:
            meta = json.load(r)["data"][0]["meta"]
        template = hashlib.sha256(props.get("chat_template", "").encode()).hexdigest()[:16]
        server = f"{meta['size']}|{meta['n_params']}|{meta.get('ftype')}|{template}|{props.get('build_info')}"
        return DiskCache(Path(path), server)
    except Exception as e:  # réponse inattendue du serveur ou base inutilisable : jamais d'appel perdu
        logger.warning("cache des réponses désactivé (%s : %s)", type(e).__name__, e)
        return False


def _separate() -> bool:
    return config.READ_LLM_URL not in ("", config.LLM_URL)


def _server(reading: bool) -> tuple[str, str]:
    """(URL, modèle) du serveur qui répond : celui de la lecture s'il est configuré, sinon le principal."""
    if reading and _separate():
        return config.READ_LLM_URL, config.READ_MODEL or config.MODEL
    return config.LLM_URL, config.MODEL


def _base_llm(max_tokens: int, cache: bool = False, reading: bool = False) -> ChatOpenAI:
    url, model = _server(reading)
    return ChatOpenAI(
        cache=_cache(config.LLM_CACHE, url) if cache else False,
        base_url=url,
        api_key="not-needed",
        model=model,
        temperature=config.LLM_TEMPERATURE,
        seed=config.LLM_SEED,
        max_tokens=max_tokens,
        timeout=config.LLM_TIMEOUT_S,
        max_retries=1,
        extra_body={"chat_template_kwargs": {"enable_thinking": False}},
    )


def get_llm(max_tokens: int, response_format: dict | None = None, reading: bool = False):
    """Modèle contraint au schéma de réponse de l'agent ; ses réponses complètes passent par le cache."""
    return _base_llm(max_tokens, cache=True, reading=reading).bind(
        response_format=response_format or prompts.RESPONSE_FORMAT
    )


def get_tool_llm(max_tokens: int):
    """Modèle autorisé à appeler les outils d'instruction (lecture seule, via le serveur MCP).

    Hors cache : chaque instruction interroge réellement le serveur de preuves.
    """
    return _base_llm(max_tokens).bind_tools(prompts.INSTRUCTION_TOOLS)


def slot(reading: bool = False) -> asyncio.Semaphore:
    """Un appel au modèle par slot du serveur d'inférence, quel que soit le nombre de branches."""
    separate = reading and _separate()
    key = (id(asyncio.get_running_loop()), separate)
    if key not in _semaphores:
        _semaphores[key] = asyncio.Semaphore(config.READ_PARALLEL if separate else config.LLM_PARALLEL)
    return _semaphores[key]


async def ask(
    agent: str,
    system: str,
    user: str,
    max_tokens: int,
    response_format: dict | None = None,
    reading: bool = False,
) -> tuple[str, list[str], dict[str, Any]]:
    """Appelle le modèle (`reading` : celui de la lecture). Renvoie (texte, anomalies, mesures)."""
    stats: dict[str, Any] = {
        "agent": agent,
        "prompt_chars": len(system) + len(user),
        "model": _server(reading)[1],
    }
    async with slot(reading):
        started = time.monotonic()
        try:
            resp = await get_llm(max_tokens, response_format, reading=reading).ainvoke(
                [SystemMessage(content=system), HumanMessage(content=user)]
            )
        except Exception as e:
            stats["seconds"] = round(time.monotonic() - started, 1)
            # réponse arrêtée par la limite de longueur : le texte existe
            cut = getattr(e, "completion", None)
            if cut is not None and cut.choices:
                stats["completion_tokens"] = getattr(cut.usage, "completion_tokens", None)
                stats["prompt_tokens"] = getattr(cut.usage, "prompt_tokens", None)
                text = (cut.choices[0].message.content or "").strip()
                return text, [f"{agent} : réponse coupée à {max_tokens} tokens"], stats
            # serveur injoignable, délai dépassé… : l'exécution continue et le rapport le dit
            logger.exception("appel au modèle en échec (%s)", agent)
            return "", [f"{agent} : appel au modèle en échec ({type(e).__name__} : {e})"], stats
    content = resp.content
    if isinstance(content, list):  # réponse en blocs : seul le texte compte
        content = "".join(b.get("text", "") for b in content if isinstance(b, dict))
    text = str(content).strip()
    usage = getattr(resp, "usage_metadata", None) or {}
    cached = "total_cost" in usage  # LangChain marque ainsi une réponse relue du cache
    stats.update(  # relue du cache : aucun token traité ni généré par cet appel
        cached=cached,
        seconds=round(time.monotonic() - started, 1),
        prompt_tokens=0 if cached else usage.get("input_tokens"),
        completion_tokens=0 if cached else usage.get("output_tokens"),
    )
    problems = []
    if not text:
        problems.append(f"{agent} : le modèle a renvoyé une réponse vide")
    finish = (resp.response_metadata or {}).get("finish_reason")
    if finish == "length":
        problems.append(f"{agent} : réponse coupée à {max_tokens} tokens")
    elif finish not in (None, "stop"):
        problems.append(f"{agent} : fin de réponse anormale ({finish})")
    return text, problems, stats


async def run_agent(
    agent: str,
    system: str,
    user: str,
    max_tokens: int,
    index: dict,
    allowed: set[str],
    run_dir: str,
    response_format: dict | None = None,
    check: Callable[[dict[str, Any]], str | None] | None = None,
    reading: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    """Un appel au modèle, le contrôle de ses constats, et une relance s'il y a des rejets.

    `check(constat)` ajoute les règles propres à l'agent (catégorie, numéro de scénario…) : il rend
    un motif de rejet ou None. Les champs de premier niveau de la réponse sont rendus dans `extra`.
    """
    raw_dir = Path(run_dir) / "llm"
    raw_dir.mkdir(exist_ok=True)
    calls: list[dict[str, Any]] = []

    async def attempt(n: int, prompt: str) -> tuple[dict[str, Any], list[str], bool]:
        text, problems, stats = await ask(agent, system, prompt, max_tokens, response_format, reading)
        calls.append(stats)
        (raw_dir / f"{agent}_{n}.prompt.txt").write_text(f"{system}\n\n{prompt}", encoding="utf-8")
        (raw_dir / f"{agent}_{n}.txt").write_text(text, encoding="utf-8")
        findings, top, shape_error = parse_answer(text)
        if shape_error and text:
            problems.append(f"{agent} : {shape_error}")
        verified, rejected = validate(findings, index, allowed)
        if check:
            kept = []
            for f in verified:
                reason = check(f)
                if reason:
                    rejected.append({**f, "reasons": [reason]})
                else:
                    kept.append(f)
            verified = kept
        limits = top.pop("limits", "")
        return (
            {"verified": verified, "rejected": rejected, "limits": limits, "extra": top},
            problems,
            shape_error is None,
        )

    result, problems, readable = await attempt(1, user)
    unreadable = 0 if readable else 1
    first = {"verified": len(result["verified"]), "rejected": len(result["rejected"])}
    retried = bool(result["rejected"])
    if retried:
        second, problems2, readable = await attempt(2, f"{user}\n\n{rejection_feedback(result['rejected'])}")
        problems += problems2
        if readable:  # une relance illisible ne doit pas effacer les constats déjà vérifiés
            result = second
        else:
            unreadable += 1
        if result["rejected"]:
            problems.append(f"{agent} : {len(result['rejected'])} constat(s) rejeté(s) après relance")
    return {
        **result,
        "retried": retried,
        "first_attempt": first,
        "unreadable": unreadable,
        "calls": calls,
    }, problems


def merge(parts: list[dict[str, Any]]) -> dict[str, Any]:
    """Réunit les résultats des lots d'un même agent."""
    limits = list(dict.fromkeys(p["limits"] for p in parts if p["limits"]))
    return {
        "verified": [f for p in parts for f in p["verified"]],
        "rejected": [f for p in parts for f in p["rejected"]],
        "limits": " ".join(limits),
        "retried": any(p["retried"] for p in parts),
        "first_attempt": {k: sum(p["first_attempt"][k] for p in parts) for k in ("verified", "rejected")},
        "unreadable": sum(p["unreadable"] for p in parts),
        "calls": [c for p in parts for c in p["calls"]],
        "chunks": len(parts),
    }


def empty(limits: str) -> dict[str, Any]:
    return {"verified": [], "rejected": [], "limits": limits, "retried": False, "calls": [], "chunks": 0}


def overhead(spec: dict) -> int:
    """Caractères du prompt hors données : consignes, règles, relance éventuelle."""
    return (
        len(spec["system"])
        + len(spec["task"])
        + len(prompts.INTEGRITY_RULE)
        + len(prompts.OUTPUT_RULES)
        + 2500
    )
