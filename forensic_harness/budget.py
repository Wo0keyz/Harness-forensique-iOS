"""Budget de contexte : combien de caractères de données tiennent dans un appel au modèle.

Mesuré sur le serveur d'inférence (taille de contexte par slot, tokenisation réelle d'un
échantillon des données) plutôt que supposé : sur des lignes de preuve pleines d'horodatages et
d'identifiants, un token ne vaut qu'environ 2 caractères, loin des 3 à 4 du texte courant.
"""

import asyncio
import json
import logging
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any

from forensic_harness import config

logger = logging.getLogger(__name__)
SAMPLE_CHARS = 20_000


@dataclass(frozen=True)
class Budget:
    n_ctx: int  # tokens de contexte par slot
    chars_per_token: float
    measured: bool  # False : serveur injoignable, valeurs prudentes de la configuration

    def chunk_chars(self, max_tokens: int, overhead_chars: int, whole_context: bool = False) -> int:
        """Taille maximale, en caractères, des données d'un appel.

        Les lots de preuves sont bornés par CHUNK_TOKENS ; `whole_context` lève cette borne pour
        les appels qui doivent tout voir d'un coup (corrélation, synthèse, condensation).
        """
        overhead = overhead_chars / self.chars_per_token
        room = self.n_ctx - max_tokens - overhead - 0.05 * self.n_ctx  # 5 % de marge
        tokens = room if whole_context else min(config.CHUNK_TOKENS, room)
        return max(1000, int(tokens * self.chars_per_token))

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _server(path: str, payload: dict | None = None, base: str = "") -> Any:
    url = (base or config.LLM_URL).removesuffix("/").removesuffix("/v1") + path
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data, {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 (URL locale de configuration)
        return json.load(resp)


def _measure(sample: str) -> Budget:
    try:  # serveur de lecture séparé : le plus petit contexte et la tokenisation la plus dense des deux
        found = []
        for base in dict.fromkeys([config.LLM_URL, config.READ_LLM_URL or config.LLM_URL]):
            n_ctx = int(_server("/props", base=base)["default_generation_settings"]["n_ctx"])
            tokens = len(_server("/tokenize", {"content": sample}, base)["tokens"])
            found.append((n_ctx, max(1.0, len(sample) / max(1, tokens))))
        return Budget(min(n for n, _ in found), min(c for _, c in found), True)
    except (OSError, ValueError, KeyError, TypeError) as e:
        logger.warning("budget de contexte non mesurable (%s) : valeurs par défaut prudentes", e)
        return Budget(config.CTX_TOKENS, config.CHARS_PER_TOKEN, False)


async def measure(sample: str) -> Budget:
    return await asyncio.to_thread(_measure, sample[:SAMPLE_CHARS] or "x")
