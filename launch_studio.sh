#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$DIR/.venv"

echo "=========================================================="
echo "   🚀 Démarrage de LangGraph Studio (Interface Graphique) "
echo "=========================================================="
echo "API locale uniquement (127.0.0.1:2024), sans tunnel public."
echo "Accès distant : ssh -L 2024:localhost:2024 <cette-machine>"
echo "=========================================================="

# Pas de --tunnel ni de 0.0.0.0 : l'API dev n'a pas d'authentification et lit des preuves.
"$VENV/bin/langgraph" dev --port 2024 --host 127.0.0.1 --studio-url https://eu.smith.langchain.com "$@"
