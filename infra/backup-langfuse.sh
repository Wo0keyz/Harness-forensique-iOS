#!/bin/bash
# Sauvegarde des volumes de Langfuse (traces, prompts, scores). Les services sont arrêtés
# proprement le temps de la copie, puis relancés quoi qu'il arrive (erreur, Ctrl-C, coupure SSH).
# Ne pas lancer pendant une analyse : les traces de l'exécution en cours seraient perdues.
#
#   infra/backup-langfuse.sh [dossier du compose Langfuse] [dossier de destination]
#
# Le fichier .env de Langfuse (ENCRYPTION_KEY, SALT) n'est PAS copié : sans lui, une restauration
# ne peut pas déchiffrer les données. Le conserver à part, en lieu sûr.
set -euo pipefail
COMPOSE_DIR="${1:-$HOME/langfuse-local}"
DEST="${2:-$HOME/backups/langfuse}/$(date -u +%Y%m%dT%H%M%SZ)"
# image déjà présente sur la machine (celle de Postgres, épinglée) : aucun téléchargement pour sauvegarder
IMAGE="docker.io/postgres@sha256:f4c66b820c6f974249089d3d16d86a3698eae11e8746eb6644b2271031e91232"
mkdir -p "$DEST"
chmod 700 "$DEST"

cd "$COMPOSE_DIR"
PROJECT="$(docker compose config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')"
trap 'docker compose start' EXIT
trap 'exit 1' INT TERM HUP
docker compose stop -t 120   # laisse aux bases le temps de s'arrêter proprement

for volume in $(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT"); do
  echo "sauvegarde de $volume"
  docker run --rm -v "$volume:/v:ro" -v "$DEST:/out" "$IMAGE" \
    sh -c "tar -C /v -czf /out/$volume.tar.gz . && chown $(id -u):$(id -g) /out/$volume.tar.gz"
done
( cd "$DEST" && sha256sum ./*.tar.gz > SHA256SUMS && chmod 600 ./* )
echo "Sauvegarde écrite dans $DEST"
