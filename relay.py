"""Le relais : il représente le réseau entre Alice et Bob, et il est contrôlé par Eve.

Tous les messages passent par lui. En mode passif, Eve copie et laisse passer.
En mode actif, chaque message est retenu jusqu'à ce qu'Eve décide : transmettre, altérer, remplacer ou bloquer.

    python relay.py --port 5000
Au démarrage, le relais affiche l'adresse à donner aux participants (ex. http://192.168.1.10:5000).
L'interface d'Eve est sur http://localhost:5000 (accessible uniquement depuis la machine du relais).
Sous WSL2, --wsl-forward ouvre le port côté Windows pour que les autres machines puissent se connecter.
"""
import argparse
import logging
import copy
import functools
import itertools
import threading
import time
from pathlib import Path

import flask.cli
from flask import Flask, abort, jsonify, request, send_from_directory

from common import netinfo
from common.schemes import SCHEMES

WEB = Path(__file__).parent / "web"
LOCAL_ADDRS = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}

app = Flask(__name__, static_folder=str(WEB), static_url_path="/static")
app.json.sort_keys = False  # garder l'ordre RSA, ECC, El-Gamal
lock = threading.RLock()
ids = itertools.count(1)
eve_keys = {sid: s.generate_keys() for sid, s in SCHEMES.items()}
state = {
    "mode": "passive",
    "participants": {},  # nom -> {public, addr, last_seen}
    "inboxes": {},       # nom -> [paquets à livrer]
    "packets": [],       # journal complet vu par Eve
    "stolen": {},        # nom -> clé privée El-Gamal retrouvée par Eve
    "attack_results": {},  # "id1-id2" -> {victim, success, steps}
    "eve_public": False,
    "network": {},       # adresse à communiquer aux participants (voir common/netinfo.py)
}


def error(message, status=400):
    return jsonify({"error": message}), status


def directory():
    return {name: p["public"] for name, p in state["participants"].items()}


def deliver(packet):
    packet["delivered_at"] = time.time()
    state["inboxes"].setdefault(packet["to"], []).append({
        k: packet[k] for k in ("id", "time", "scheme", "from", "to")
    } | {"payload": copy.deepcopy(packet["payload"])})


# --- API des participants (Alice, Bob…) -------------------------------------

@app.post("/api/register")
def register():
    body = request.get_json(force=True)
    name = (body.get("name") or "").strip()
    public = body.get("public") or {}
    if not name or len(name) > 32:
        return error("Nom invalide")
    if set(public) != set(SCHEMES):
        return error("Clés publiques incomplètes")
    with lock:
        existing = state["participants"].get(name)
        if existing and existing["public"] != public and time.time() - existing["last_seen"] < 5:
            return error(f"Le nom « {name} » est déjà utilisé par quelqu'un de connecté", 409)
        # L'adresse annoncée par le client est plus parlante que remote_addr derrière une redirection WSL.
        addr = body.get("lan_ip") or request.remote_addr
        state["participants"][name] = {"public": public, "addr": addr, "last_seen": time.time()}
        state["inboxes"].setdefault(name, [])
    return jsonify({"ok": True})


@app.get("/api/directory")
def get_directory():
    with lock:
        return jsonify(directory())


@app.post("/api/send")
def send():
    body = request.get_json(force=True)
    sender, recipient, scheme = body.get("from"), body.get("to"), body.get("scheme")
    with lock:
        if sender not in state["participants"] or recipient not in state["participants"]:
            return error("Expéditeur ou destinataire inconnu du relais", 404)
        if scheme not in SCHEMES:
            return error("Schéma inconnu")
        packet = {
            "id": next(ids), "time": time.time(), "scheme": scheme, "from": sender, "to": recipient,
            "payload": body.get("payload") or {}, "status": "transmis", "notes": [], "eve_read": None,
        }
        packet["original"] = copy.deepcopy(packet["payload"])
        state["packets"].append(packet)
        if state["mode"] == "active":
            packet["status"] = "en_attente"
        else:
            deliver(packet)
    return jsonify({"id": packet["id"], "time": packet["time"]})


@app.get("/api/inbox/<name>")
def inbox(name):
    with lock:
        if name not in state["participants"]:
            return error("Participant inconnu", 404)
        state["participants"][name]["last_seen"] = time.time()
        items, state["inboxes"][name] = state["inboxes"][name], []
    return jsonify(items)


# --- Interface et API d'Eve -------------------------------------------------

def eve_only(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not state["eve_public"] and request.remote_addr not in LOCAL_ADDRS:
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def find_packet(pid):
    for p in state["packets"]:
        if p["id"] == pid:
            return p
    abort(404)


def held_packet(pid):
    packet = find_packet(pid)
    if packet["status"] != "en_attente":
        abort(409)
    return packet


def packet_view(p):
    modes = ["keep", "none", "eve"]
    if p["scheme"] == "elgamal" and p["from"] in state["stolen"]:
        modes.append("stolen")
    return {k: p[k] for k in ("id", "time", "scheme", "from", "to", "status", "payload", "notes", "eve_read")} | {
        "modified": p["payload"] != p["original"], "replace_modes": modes,
    }


@app.get("/")
@eve_only
def eve_page():
    return send_from_directory(WEB, "eve.html")


@app.get("/eve/api/state")
@eve_only
def eve_state():
    with lock:
        now = time.time()
        participants = [{
            "name": name, "addr": p["addr"], "online": now - p["last_seen"] < 5,
            "fingerprints": {sid: SCHEMES[sid].fingerprint(p["public"][sid]) for sid in SCHEMES},
        } for name, p in state["participants"].items()]
        attacks = []
        for a in SCHEMES["elgamal"].find_reused_k(state["packets"]):
            result = state["attack_results"].get("-".join(map(str, a["ids"])))
            if a["victim"] in state["stolen"] and not (result and result["success"]):
                continue  # clé déjà volée via une autre paire
            attacks.append(a | {"result": result})
        return jsonify({
            "mode": state["mode"],
            "participants": participants,
            "packets": [packet_view(p) for p in reversed(state["packets"])],
            "attacks": attacks,
            "stolen": sorted(state["stolen"]),
            "schemes": {sid: s.LABEL for sid, s in SCHEMES.items()},
            "network": state["network"],
        })


@app.post("/eve/api/mode")
@eve_only
def eve_mode():
    mode = request.get_json(force=True).get("mode")
    if mode not in ("passive", "active"):
        return error("Mode inconnu")
    with lock:
        state["mode"] = mode
        if mode == "passive":
            for p in state["packets"]:
                if p["status"] == "en_attente":
                    p["status"] = "transmis"
                    deliver(p)
    return jsonify({"ok": True})


@app.post("/eve/api/packets/<int:pid>/read")
@eve_only
def eve_read(pid):
    with lock:
        packet = find_packet(pid)
        scheme = SCHEMES[packet["scheme"]]
        packet["eve_read"] = scheme.eve_read(eve_keys[scheme.ID], packet, directory(), state["stolen"])
        return jsonify(packet_view(packet))


@app.post("/eve/api/packets/<int:pid>/<action>")
@eve_only
def eve_action(pid, action):
    body = request.get_json(silent=True) or {}
    with lock:
        packet = held_packet(pid)
        scheme = SCHEMES[packet["scheme"]]
        if action == "forward":
            packet["status"] = "transmis"
        elif action == "block":
            packet["status"] = "bloque"
            packet["notes"].append("Message bloqué : il n'arrivera jamais.")
            return jsonify(packet_view(packet))
        elif action == "tamper":
            packet["payload"], note = scheme.eve_tamper(packet["payload"])
            packet["notes"].append(note)
            packet["status"] = "modifie"
        elif action == "replace":
            text = (body.get("text") or "").strip()
            if not text:
                return error("Texte vide")
            packet["payload"], note = scheme.eve_replace(eve_keys[scheme.ID], packet, directory(), text,
                                                         body.get("signature", "keep"), state["stolen"])
            packet["notes"].append(note)
            packet["status"] = "modifie"
        else:
            abort(404)
        deliver(packet)
        return jsonify(packet_view(packet))


@app.post("/eve/api/attack/elgamal")
@eve_only
def eve_attack():
    ids_ = request.get_json(force=True).get("ids") or []
    if len(ids_) != 2:
        return error("Il faut exactement deux messages")
    with lock:
        first, second = find_packet(ids_[0]), find_packet(ids_[1])
        victim = first["from"]
        scheme = SCHEMES["elgamal"]
        x, steps = scheme.recover_key(first, second, directory()[victim]["elgamal"])
        if x is not None:
            state["stolen"][victim] = x
        result = {"victim": victim, "success": x is not None, "steps": steps}
        state["attack_results"][f"{first['id']}-{second['id']}"] = result
        return jsonify(result)


def print_banner(port, net):
    line = "─" * 64
    print(f"\n{line}\n  Relais démarré\n")
    print(f"  Adresse à donner aux participants :  {net['url']}")
    print(f"  Console d'Eve (sur cette machine)  :  http://localhost:{port}")
    if net["wsl_nat"]:
        print(f"\n  WSL2 (mode NAT) : Linux est en {net['wsl_ip']}, invisible depuis le réseau.")
        if net["forwarded"]:
            print(f"  Redirection Windows → WSL active sur le port {port} : les autres peuvent se connecter.")
        else:
            print(f"  Redirection Windows → WSL absente. Relancez avec --wsl-forward, ou exécutez")
            print("  dans un PowerShell administrateur :")
            for cmd in netinfo.forward_commands(port, net["wsl_ip"]):
                print(f"    {cmd}")
    print(f"{line}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Relais réseau contrôlé par Eve")
    parser.add_argument("--host", default="0.0.0.0", help="adresse d'écoute (0.0.0.0 = tout le réseau)")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--eve-public", action="store_true",
                        help="autoriser l'interface d'Eve depuis une autre machine")
    parser.add_argument("--wsl-forward", action="store_true",
                        help="sous WSL2 : créer la redirection de port Windows → WSL (confirmation administrateur)")
    args = parser.parse_args()
    state["eve_public"] = args.eve_public

    net = netinfo.lan_info(args.port)
    if net["wsl_nat"] and not net["forwarded"] and args.wsl_forward:
        print("Ouverture du port côté Windows : acceptez la demande d'autorisation qui s'affiche…")
        net["forwarded"] = netinfo.setup_wsl_forward(args.port, net["wsl_ip"])
    if net["wsl_nat"] and not net["forwarded"]:
        net["commands"] = netinfo.forward_commands(args.port, net["wsl_ip"])
    state["network"] = net
    print_banner(args.port, net)
    logging.getLogger("werkzeug").setLevel(logging.ERROR)  # pas une ligne par requête (sondage chaque seconde)
    flask.cli.show_server_banner = lambda *a, **k: None
    app.run(host=args.host, port=args.port, threaded=True)
