#!/bin/sh
# Isolement réseau pour l'analyse d'un vrai dossier : plus aucune sortie vers Internet, ni pour
# l'hôte ni pour les conteneurs, en IPv4 comme en IPv6. Le réseau local reste joignable.
#
#   sudo infra/airgap.sh on  192.168.137.0/24
#   sudo infra/airgap.sh off
#   sudo infra/airgap.sh status
#
# Limites : les règles ne survivent pas à un redémarrage (relancer « on ») ; le poste de
# l'analyste reste joignable, donc s'il partage sa connexion et relaie le trafic, c'est sur ce
# poste qu'il faut couper le partage. Vérifier après « on » : ping -c1 1.1.1.1 doit échouer.
set -eu
CHAIN=FORENSIC_AIRGAP
[ "$(id -u)" = 0 ] || { echo "à lancer avec sudo (sans root, l'état des règles n'est pas lisible)" >&2; exit 1; }

active() {  # les deux sauts IPv4 et le saut IPv6 sont-ils en place ?
  iptables -C OUTPUT -j "$CHAIN" 2>/dev/null && iptables -C DOCKER-USER -j "$CHAIN" 2>/dev/null \
    && ip6tables -C OUTPUT -j "$CHAIN" 2>/dev/null
}

remove() {
  for table in iptables ip6tables; do
    for hook in OUTPUT DOCKER-USER; do
      while $table -D "$hook" -j "$CHAIN" 2>/dev/null; do :; done
    done
    $table -F "$CHAIN" 2>/dev/null || true
    $table -X "$CHAIN" 2>/dev/null || true
  done
}

case "${1:-status}" in
  on)
    LAN="${2:?réseau local à laisser joignable, ex. 192.168.137.0/24}"
    remove
    trap 'remove; echo "échec : isolement non appliqué" >&2' EXIT   # jamais à moitié appliqué
    iptables -N "$CHAIN"
    iptables -A "$CHAIN" -o lo -j RETURN
    iptables -A "$CHAIN" -d 127.0.0.0/8 -j RETURN
    iptables -A "$CHAIN" -d 172.16.0.0/12 -j RETURN   # réseaux internes de Docker
    iptables -A "$CHAIN" -d "$LAN" -j RETURN
    iptables -A "$CHAIN" -j REJECT
    iptables -I OUTPUT -j "$CHAIN"
    iptables -I DOCKER-USER -j "$CHAIN"
    ip6tables -N "$CHAIN"
    ip6tables -A "$CHAIN" -o lo -j RETURN
    ip6tables -A "$CHAIN" -j REJECT
    ip6tables -I OUTPUT -j "$CHAIN"
    ip6tables -C DOCKER-USER -j "$CHAIN" 2>/dev/null || ip6tables -I DOCKER-USER -j "$CHAIN" 2>/dev/null || true
    trap - EXIT
    echo "Isolement ACTIF : seules les destinations locales restent joignables."
    ;;
  off)
    remove
    echo "Isolement levé."
    ;;
  status)
    if active; then echo "Isolement ACTIF"; else echo "Isolement INACTIF"; exit 1; fi
    ;;
  *) echo "usage : $0 on <réseau local> | off | status" >&2; exit 2 ;;
esac
