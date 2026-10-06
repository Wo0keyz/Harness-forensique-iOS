#!/bin/sh
# Pare-feu de la machine d'analyse. À lancer une fois, avec sudo, depuis la console ou une session
# SSH déjà ouverte (une adresse de poste erronée refuserait toute nouvelle connexion SSH).
#
#   sudo infra/firewall.sh 192.168.137.1 enp4s0     # adresse du poste de l'analyste, interface du câble
#
# Ce que le script fait :
#   - ufw : refuse tout en entrée sur l'hôte, sauf SSH depuis le poste de l'analyste ;
#   - DOCKER-USER : Langfuse (port 3000, publié par Docker) n'est joignable que depuis ce poste.
# ufw seul ne suffit pas : Docker publie ses ports en amont de ufw. Les autres services (inférence,
# MinIO, bases) doivent rester liés à 127.0.0.1 dans les fichiers compose ; le script le vérifie.
# Les règles DOCKER-USER ne survivent pas à un redémarrage : relancer le script après un reboot.
set -eu
LAPTOP="${1:?adresse IP du poste de l'analyste}"
IFACE="${2:?interface réseau du câble vers ce poste (voir: ip -br a)}"
[ "$(id -u)" = 0 ] || { echo "à lancer avec sudo" >&2; exit 1; }

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow from "$LAPTOP" to any port 22 proto tcp comment 'SSH depuis le poste analyste'
ufw --force enable

RULE="-i $IFACE ! -s $LAPTOP -p tcp -m conntrack --ctorigdstport 3000 --ctdir ORIGINAL -j DROP"
# shellcheck disable=SC2086
iptables -C DOCKER-USER $RULE 2>/dev/null || iptables -I DOCKER-USER $RULE

ufw status verbose
echo "--- ports TCP en écoute hors localhost (attendu : 22 et 3000 seulement) ---"
ss -ltnH | awk '{print $4}' | grep -vE '^(127\.|\[::1\])' | sort -u || true
