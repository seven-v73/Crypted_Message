"""Le poste d'un participant. Chaque personne lance ce programme sur SA machine, ouvre
http://localhost:5001, choisit son nom et rejoint le relais. Ses clés privées sont générées
ici et ne quittent jamais ce processus.

    python client.py --relay http://192.168.1.10:5000
    python client.py --name Alice --relay http://192.168.1.10:5000   # rejoint directement
"""
import argparse
import logging
import threading
import time
import uuid
from pathlib import Path

import flask.cli
from flask import Flask, jsonify, request, send_from_directory

from common import netinfo
from common.http import RelayError, get_json, post_json
from common.schemes import SCHEMES

WEB = Path(__file__).parent / "web"

app = Flask(__name__, static_folder=str(WEB), static_url_path="/static")
app.json.sort_keys = False  # garder l'ordre RSA, ECC, El-Gamal
lock = threading.RLock()
cfg = {"name": None, "relay": None, "lan_ip": None}
keys = {}
public = {}
key_info = {}
peer_cache = {}  # (schéma, pair, empreinte) -> infos dérivées (secret ECDH…)
state = {"connected": False, "error": None, "directory": {}, "messages": []}


def relay_url(path):
    return cfg["relay"].rstrip("/") + path


def add_message(**entry):
    entry.setdefault("id", uuid.uuid4().hex)
    entry.setdefault("time", time.time())
    with lock:
        state["messages"].append(entry)
    return entry


def process_incoming(packet):
    scheme = SCHEMES.get(packet["scheme"])
    sender = packet["from"]
    sender_public = state["directory"].get(sender, {}).get(packet["scheme"])
    if scheme is None or sender_public is None:
        return
    try:
        text, steps, props = scheme.receive(keys[scheme.ID], sender, cfg["name"], sender_public, packet["payload"])
    except Exception as e:  # un paquet malformé ne doit pas arrêter la réception
        text, steps, props = None, [{"label": "Paquet illisible", "value": str(e), "state": "fail"}], None
    add_message(scheme=scheme.ID, direction="in", peer=sender, text=text, steps=steps, props=props,
                packet_id=packet["id"], time=packet["time"])


def register():
    if cfg["lan_ip"] is None:
        cfg["lan_ip"] = netinfo.lan_info(0)["ip"]
    post_json(relay_url("/api/register"), {"name": cfg["name"], "public": public, "lan_ip": cfg["lan_ip"]})


def network_loop():
    registered = True
    while True:
        try:
            if not registered:
                register()
                registered = True
            directory = get_json(relay_url("/api/directory"))
            with lock:
                state["directory"] = directory
            for packet in get_json(relay_url(f"/api/inbox/{cfg['name']}")):
                process_incoming(packet)
            state["connected"], state["error"] = True, None
        except RelayError as e:
            state["connected"], state["error"] = False, str(e)
            if e.status in (None, 404):  # relais redémarré ou injoignable : on se réinscrira
                registered = False
        time.sleep(1)


def join(name, relay):
    """Génère les clés de cette personne, s'inscrit au relais et démarre la réception."""
    cfg["relay"] = relay
    generated = {sid: scheme.generate_keys() for sid, scheme in SCHEMES.items()}
    for sid, scheme in SCHEMES.items():
        keys[sid] = generated[sid]
        public[sid] = scheme.export_public(generated[sid])
        key_info[sid] = scheme.key_info(generated[sid])
    cfg["name"] = name
    try:
        register()
    except RelayError:
        cfg["name"] = None
        raise
    state["connected"] = True
    threading.Thread(target=network_loop, daemon=True).start()


def peers_view():
    out = {}
    for name, pub in state["directory"].items():
        if name == cfg["name"]:
            continue
        out[name] = {}
        for sid, scheme in SCHEMES.items():
            cache_key = (sid, name, scheme.fingerprint(pub[sid]))
            if cache_key not in peer_cache:
                peer_cache[cache_key] = scheme.peer_info(keys[sid], pub[sid])
            out[name][sid] = {"fingerprint": cache_key[2], "info": peer_cache[cache_key]}
    return out


@app.get("/")
def page():
    return send_from_directory(WEB, "client.html")


@app.post("/api/join")
def api_join():
    body = request.get_json(force=True)
    name = (body.get("name") or "").strip()
    relay = (body.get("relay") or "").strip()
    if cfg["name"]:
        return jsonify({"error": "Ce poste a déjà rejoint le relais"}), 409
    if not name or len(name) > 24:
        return jsonify({"error": "Choisissez un nom de 1 à 24 caractères"}), 400
    if not relay.startswith(("http://", "https://")):
        relay = "http://" + relay
    try:
        with lock:
            join(name, relay)
    except RelayError as e:
        return jsonify({"error": str(e)}), 502
    return jsonify({"ok": True})


@app.get("/api/state")
def get_state():
    with lock:
        if not cfg["name"]:
            return jsonify({"joined": False, "relay": cfg["relay"]})
        return jsonify({
            "joined": True,
            "me": cfg["name"],
            "relay": cfg["relay"],
            "connected": state["connected"],
            "error": state["error"],
            "peers": peers_view(),
            "messages": state["messages"],
            "keys": {sid: {"info": key_info[sid], "fingerprint": SCHEMES[sid].fingerprint(public[sid])}
                     for sid in SCHEMES},
            "schemes": {sid: s.LABEL for sid, s in SCHEMES.items()},
        })


@app.post("/api/send")
def send():
    if not cfg["name"]:
        return jsonify({"error": "Rejoignez d'abord le relais"}), 409
    body = request.get_json(force=True)
    scheme = SCHEMES.get(body.get("scheme"))
    recipient = body.get("to")
    text = (body.get("text") or "").strip()
    options = body.get("options") or {}
    if scheme is None or not text:
        return jsonify({"error": "Message vide"}), 400
    recipient_public = state["directory"].get(recipient, {}).get(scheme.ID)
    if recipient_public is None:
        return jsonify({"error": f"{recipient} n'est pas connecté au relais"}), 404

    with lock:
        payload, steps = scheme.send(keys[scheme.ID], cfg["name"], recipient, recipient_public, text, options)
    try:
        sent = post_json(relay_url("/api/send"), {"from": cfg["name"], "to": recipient,
                                                  "scheme": scheme.ID, "payload": payload})
    except RelayError as e:
        return jsonify({"error": str(e)}), 502
    steps.append({"label": "Paquet remis au relais", "value": f"n° {sent['id']}", "state": "ok"})
    entry = add_message(scheme=scheme.ID, direction="out", peer=recipient, text=text, steps=steps,
                        options=options, packet_id=sent["id"], time=sent["time"])
    return jsonify(entry)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Poste d'un participant")
    parser.add_argument("--name", help="rejoindre directement sous ce nom (sinon : choisi dans le navigateur)")
    parser.add_argument("--relay", default="http://127.0.0.1:5000", help="adresse du relais d'Eve")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--host", default="127.0.0.1",
                        help="adresse de l'interface (127.0.0.1 : seule cette machine voit vos clés)")
    args = parser.parse_args()
    cfg["relay"] = args.relay

    if args.name:
        print(f"Génération des clés de {args.name}…")
        try:
            join(args.name.strip(), args.relay)
        except RelayError as e:
            print(f"Impossible de rejoindre le relais ({e}). Réessayez depuis le navigateur.")
    print(f"Ouvrir http://localhost:{args.port} dans le navigateur de cette machine (relais : {args.relay})")
    logging.getLogger("werkzeug").setLevel(logging.ERROR)  # pas une ligne par requête (sondage chaque seconde)
    flask.cli.show_server_banner = lambda *a, **k: None
    app.run(host=args.host, port=args.port, threaded=True)
