#!/usr/bin/env bash
# Lance le relais d'Eve, Alice et Bob sur la même machine (pour tester avant de passer en réseau).
cd "$(dirname "$0")"
PY="python3 -u"
[ -x .venv/bin/python ] && PY=".venv/bin/python -u"
trap 'kill 0' EXIT
$PY relay.py --port 5000 &
sleep 3   # le relais détecte son adresse réseau

$PY client.py --port 5001 --relay http://127.0.0.1:5000 &
$PY client.py --port 5002 --relay http://127.0.0.1:5000 &
sleep 2
echo
echo "  Eve   : http://localhost:5000"
echo "  Poste 1 : http://localhost:5001  (choisissez un nom, ex. Alice)"
echo "  Poste 2 : http://localhost:5002  (ex. Bob)"
echo "  (Ctrl+C pour tout arrêter)"
wait
