"""Configuration lue dans l'environnement (fichier .env à la racine du dépôt, jamais versionné)."""

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

# Aucune donnée de dossier ne part dans le cloud : le traçage LangSmith est coupé dans le code,
# quoi que dise l'environnement. Les traces vont dans Langfuse auto-hébergé.
for _name in ("LANGSMITH_TRACING", "LANGSMITH_TRACING_V2", "LANGCHAIN_TRACING", "LANGCHAIN_TRACING_V2"):
    os.environ[_name] = "false"

LLM_URL = os.getenv("LLAMA_SERVER_URL", "http://localhost:8080/v1")
MODEL = os.getenv("MODEL_NAME", "qwen3.8:latest")
# Serveur de la lecture des preuves (la majorité des appels), s'il diffère : un modèle MoE y lit plus vite
# (infra/docker-compose.moe.yml). Vide = le serveur principal. Hypothèses, enquête et rédaction restent
# sur le serveur principal.
READ_LLM_URL = os.getenv("READ_LLM_URL", "")
READ_MODEL = os.getenv("READ_MODEL_NAME", "")
READ_LLM_CONTAINER = os.getenv("READ_LLM_CONTAINER", "llama-moe")
DEFAULT_CASE = os.getenv("CASE_PATH", "")
RUNS_DIR = Path(os.getenv("RUNS_DIR", str(ROOT / "runs")))

# Cache des réponses complètes du modèle (SQLite). Vide = coupé : à faire pour mesurer la variance
# entre exécutions, sinon la deuxième relit la première.
LLM_CACHE = os.getenv("LLM_CACHE", str(RUNS_DIR / "llm_cache.sqlite"))

LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.1"))
LLM_TIMEOUT_S = float(os.getenv("LLM_TIMEOUT_S", "3600"))
LLM_SEED = int(os.getenv("LLM_SEED", "0"))  # graine fixe : même entrée, même tirage
# Conteneur Docker du serveur d'inférence, interrogé pour le manifeste (image, arguments, modèle).
LLM_CONTAINER = os.getenv("LLM_CONTAINER", "llama-server")

# Données par lot, en tokens. Plus petit = appels plus nombreux mais plus rapides et mieux lus par un
# petit modèle ; le plafond réel est le contexte du serveur, mesuré à chaque exécution.
CHUNK_TOKENS = int(os.getenv("CHUNK_TOKENS", "8000"))
# Valeurs utilisées seulement si le serveur d'inférence ne répond pas à la mesure du budget.
CTX_TOKENS = int(os.getenv("CTX_TOKENS", "16384"))
CHARS_PER_TOKEN = float(os.getenv("CHARS_PER_TOKEN", "2.0"))

# Appels simultanés au modèle (nombre de slots du serveur d'inférence).
LLM_PARALLEL = int(os.getenv("LLM_PARALLEL", "4"))
READ_PARALLEL = int(os.getenv("READ_PARALLEL", "2"))  # slots du serveur de lecture, s'il est séparé
# Au-delà de ce nombre de constats vérifiés, un domaine est condensé avant l'enquête.
MAX_FINDINGS = int(os.getenv("MAX_FINDINGS", "40"))
# Enquête : scénarios instruits au plus, tours d'outils par instruction (trois appels par tour),
# lignes rendues au modèle par appel d'outil, reprises de l'instruction demandées par le contradicteur.
MAX_SCENARIOS = int(os.getenv("MAX_SCENARIOS", "4"))
INSTRUCTION_ROUNDS = int(os.getenv("INSTRUCTION_ROUNDS", "4"))
TOOL_ROWS = int(os.getenv("TOOL_ROWS", "40"))
COUNTER_ROUNDS = int(os.getenv("COUNTER_ROUNDS", "1"))
# Catalogue des qualifications envisageables (droit applicable). Son empreinte entre dans celle des prompts.
QUALIFICATIONS = Path(os.getenv("QUALIFICATIONS", str(Path(__file__).with_name("qualifications_ch.json"))))

# Longueur maximale d'un champ transmis au modèle ; au-delà, la coupe est marquée dans le texte.
MAX_FIELD_CHARS = int(os.getenv("MAX_FIELD_CHARS", "1000"))
