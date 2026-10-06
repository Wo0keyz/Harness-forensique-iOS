#!/bin/bash
# Évaluation à n exécutions par cas, cache des réponses coupé (sinon la 2e exécution relit la 1re et la
# dispersion mesurée est nulle). Lancée depuis un clone figé à l'étiquette donnée, dans tmux :
#
#   tmux new -d -s eval 'bash infra/evaluation.sh phase36-fixes 3'
#   READ_LLM_URL=http://localhost:8081/v1 READ_MODEL_NAME=qwen3.6-35b-a3b bash infra/evaluation.sh phase36-fixes 3 moe
#
# Cas : Magnet (public, réglage), témoins synthétiques ambigu et sans histoire, et Hickman iOS 17
# (public, tenu à l'écart : jamais utilisé pour régler les prompts) si sa sortie iLEAPP existe.
set -u
TAG=${1:?étiquette git à évaluer}
N=${2:-3}
V=$HOME/forensic-langgraph/runs/real/eval-$TAG${3:+-$3}  # 3e argument : variante (même code)
F=$V/frozen
mkdir -p "$V"
[ -d "$F" ] || git clone -q $HOME/forensic-langgraph "$F"
cd "$F" && git checkout -q "$TAG" || exit 1
[ -d .venv ] || ln -s $HOME/forensic-langgraph/.venv .venv
set -a; . $HOME/forensic-langgraph/.env; set +a
export RUNS_DIR=$V/runs LLM_CACHE=
log() { echo "$(date -Is) $*" >> "$V/journal.txt"; }
run() {  # nom, jeu de données, dossier du cas, puis options d'evaluate (ex. --gate)
  [ -d "$3" ] || { log "$1 : cas absent ($3), ignoré"; return; }
  log "$1 : début ($N exécutions)"
  .venv/bin/python -m forensic_harness.evaluate --dataset "$2" --case "$3" --runs "$N" --out "$V/eval" "${@:4}" > "$V/$1.log" 2>&1
  log "$1 : fin, code $?"
}
[ -d "$V/cases/synthetic-ambiguous" ] || .venv/bin/python -m forensic_harness.synthetic_case "$V/cases/synthetic-ambiguous" --ambigu
[ -d "$V/cases/synthetic-benign" ] || .venv/bin/python -m forensic_harness.synthetic_case "$V/cases/synthetic-benign"
log "évaluation $TAG ${3:-} démarrée (lecture : ${READ_LLM_URL:-serveur principal})"
run magnet datasets/magnet_ground_truth.json $HOME/iPhone14Plus-CTF-MAGNET-iLEAPP_Output
run hickman datasets/hickman_ios17.json $HOME/cases/iOS17-Hickman-iLEAPP_Output
run ambigu datasets/synthetic_ambiguous.json "$V/cases/synthetic-ambiguous" --gate $HOME/forensic-langgraph/datasets/gate_temoin.json
run benign datasets/synthetic_benign.json "$V/cases/synthetic-benign" --gate $HOME/forensic-langgraph/datasets/gate_temoin.json
{
  echo "# Évaluation $TAG, $N exécutions par cas ($(date -Is))"
  for n in magnet hickman ambigu benign; do
    echo; echo "## $n"; echo
    [ -f "$V/$n.log" ] || { echo "Non évalué (dossier absent : voir journal.txt)."; continue; }
    sed -n '/^Jeu :/,/^Détail/p' "$V/$n.log"
  done
} > "$V/RESULTATS.md"
log "évaluation $TAG terminée"
