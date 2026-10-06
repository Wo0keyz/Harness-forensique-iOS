"""Accès au serveur iLEAPP-MCP : un processus serveur par cas, chargé explicitement.

Tous les accès aux preuves passent par `CaseSession.call`, qui journalise l'appel
(outil, arguments, empreinte du résultat). Aucune erreur n'est avalée.
"""

import hashlib
import json
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PAGE = 250  # taille de page maximale acceptée par les outils paginés du serveur


class ToolError(RuntimeError):
    """Le serveur MCP a renvoyé une erreur pour un appel d'outil."""


class CaseSession:
    def __init__(self, session: ClientSession, case_path: Path):
        self._session = session
        self.case_path = case_path
        self.journal: list[dict[str, Any]] = []

    async def call(self, tool: str, **args: Any) -> Any:
        started = time.monotonic()
        result = await self._session.call_tool(tool, args)
        text = "\n".join(c.text for c in result.content if getattr(c, "text", None))
        entry = {
            "at": datetime.now(UTC).isoformat(timespec="seconds"),
            "tool": tool,
            "args": args,
            "duration_ms": round((time.monotonic() - started) * 1000),
        }
        if result.isError:
            self.journal.append({**entry, "error": text})
            raise ToolError(f"{tool}({args}) : {text}")
        data = result.structuredContent if result.structuredContent is not None else json.loads(text)
        if isinstance(data, dict) and set(data) == {"result"}:
            data = data["result"]
        canonical = json.dumps(data, sort_keys=True, ensure_ascii=False).encode()
        self.journal.append({**entry, "result_sha256": hashlib.sha256(canonical).hexdigest()})
        return data

    async def fetch_all(self, tool: str, **args: Any) -> tuple[list[dict], int, int]:
        """Parcourt toutes les pages d'un outil paginé.

        Renvoie (éléments, total côté serveur, lignes que le serveur a écartées car sans contenu).
        """
        items: list[dict] = []
        offset = 0
        while True:
            page = await self.call(tool, limit=PAGE, offset=offset, **args)
            items.extend(page["items"])
            if not page["has_more"]:
                return items, page["total_count"], page.get("skipped_empty", 0)
            offset += PAGE


@asynccontextmanager
async def open_case(case_path: str | Path) -> AsyncIterator[CaseSession]:
    """Démarre un serveur MCP dédié au cas et vérifie qu'il sert bien ce cas-là."""
    case = Path(case_path).resolve()
    if not case.is_dir():
        raise FileNotFoundError(f"Dossier de cas introuvable : {case}")
    params = StdioServerParameters(command=sys.executable, args=["-m", "ileapp_mcp.cli", str(case)])
    try:
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            cs = CaseSession(session, case)
            info = await cs.call("get_case_info")
            if not info["loaded"] or Path(info["case_path"]).resolve() != case:
                raise ToolError(f"Le serveur MCP ne sert pas le cas demandé ({case}) : {info}")
            if not info["total_artifacts"]:
                raise ToolError(f"Aucun export iLEAPP trouvé dans {case} : ce n'est pas une sortie iLEAPP")
            if info.get("index_truncated"):
                raise ToolError(f"Index du cas tronqué côté serveur MCP : analyse refusée ({case})")
            yield cs
    except BaseExceptionGroup as group:
        # le client MCP enveloppe toute erreur dans des groupes imbriqués : on rend l'erreur d'origine
        exc: BaseException = group
        while isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) == 1:
            exc = exc.exceptions[0]
        raise exc from None
