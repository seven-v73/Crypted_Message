"""El-Gamal : sécurité de la transmission (chiffrement), signature numérique, authenticité et intégrité."""
from common.codec import alter_text, sha256_hex, step
from common.guarantees import signed_message
from elgamal_demo import elgamal as eg

ID = "elgamal"
LABEL = "El-Gamal"


# --- Clés ------------------------------------------------------------------

def generate_keys():
    x, y = eg.generate_keys()
    return {"x": x, "y": y, "fixed_k": None}


def export_public(keys):
    return {"y": f"{keys['y']:x}", "g": eg.G, "p_bits": eg.P_BITS}


def _y(public):
    return int(public["y"], 16)


def fingerprint(public):
    return sha256_hex(public["y"].encode())[:16]


def key_info(keys):
    return [
        {"label": f"Nombre premier p ({eg.P_BITS} bits, RFC 3526, public et commun)", "value": f"{eg.P:x}"},
        {"label": "Générateur g (public et commun)", "value": str(eg.G)},
        {"label": "Clé publique y = g^x mod p", "value": f"{keys['y']:x}"},
        {"label": "Clé privée x", "value": f"{keys['x']:x}", "secret": True},
    ]


def peer_info(keys, peer_public):
    return []


# --- Envoi / réception -----------------------------------------------------

def _encode_blocks(blocks):
    return [[f"{c1:x}", f"{c2:x}"] for c1, c2 in blocks]


def _decode_blocks(blocks):
    return [(int(c1, 16), int(c2, 16)) for c1, c2 in blocks]


def _format_blocks(blocks):
    return "\n\n".join(f"c₁ = {c1}\nc₂ = {c2}" for c1, c2 in blocks)


def send(keys, sender, recipient, recipient_public, text, options):
    data = text.encode()
    encrypted = bool(options.get("encrypt", True))
    payload = {"encrypted": encrypted, "signature": None}
    h = eg.hash_int(data)
    steps = [step("H(m) : empreinte SHA-256 du message, vue comme un entier", f"{h:x}")]

    if options.get("sign", True):
        if options.get("reuse_k"):
            if keys["fixed_k"] is None:
                keys["fixed_k"] = eg.random_k()
            r, s = eg.sign(h, keys["x"], keys["fixed_k"])
            steps.append(step("Même k que pour la signature précédente (faille volontaire)",
                              "Deux signatures avec le même k suffisent à retrouver la clé privée x.", "warn"))
        else:
            r, s = eg.sign(h, keys["x"])
        payload["signature"] = {"r": f"{r:x}", "s": f"{s:x}"}
        steps.append(step("Signature : r = g^k mod p,  s = (H(m) − x·r)·k⁻¹ mod (p−1)",
                          f"r = {r:x}\n\ns = {s:x}", "ok"))
    else:
        steps.append(step("Pas de signature", "Le destinataire ne pourra vérifier ni l'auteur ni l'intégrité.", "warn"))

    if encrypted:
        blocks = _encode_blocks(eg.encrypt_bytes(data, _y(recipient_public)))
        payload["blocks"] = blocks
        steps.append(step(f"Chiffrement avec la clé publique y de {recipient} : "
                          f"k neuf, c₁ = g^k mod p,  c₂ = m · y^k mod p", _format_blocks(blocks), "ok"))
    else:
        payload["plaintext"] = text
        steps.append(step("Envoi en clair", "Toute personne sur le réseau pourra lire ce message.", "warn"))
    return payload, steps


def _check_signature(sender_public, signature, data):
    return eg.verify(eg.hash_int(data), int(signature["r"], 16), int(signature["s"], 16), _y(sender_public))


def receive(keys, sender, recipient, sender_public, payload):
    steps = []
    encrypted = payload.get("encrypted")
    if encrypted:
        try:
            data, well_formed = eg.decrypt_bytes(_decode_blocks(payload["blocks"]), keys["x"])
        except (ValueError, KeyError, TypeError):
            steps.append(step("Déchiffrement : m = c₂ · (c₁^x)⁻¹ mod p", "Chiffré illisible.", "fail"))
            return None, steps, signed_message(True, "tampered", sender)
        if well_formed:
            steps.append(step("Déchiffrement avec ma clé privée : m = c₂ · (c₁^x)⁻¹ mod p", None, "ok"))
        else:
            steps.append(step("Déchiffrement avec ma clé privée : m = c₂ · (c₁^x)⁻¹ mod p",
                              "Le résultat n'a pas le format attendu. El-Gamal ne détecte pas seul une "
                              "modification : seule la signature peut le faire.", "warn"))
    else:
        data = payload.get("plaintext", "").encode()
        steps.append(step("Message reçu en clair", "Il a pu être lu par n'importe qui en chemin.", "warn"))

    steps.append(step("H(m) recalculée", f"{eg.hash_int(data):x}"))
    signature = payload.get("signature")
    if signature is None:
        status = "absent"
        steps.append(step("Aucune signature jointe", None, "warn"))
    elif _check_signature(sender_public, signature, data):
        status = "valid"
        steps.append(step(f"Vérification : g^H(m) ≡ y^r · r^s (mod p) avec la clé publique de {sender}",
                          "Égalité vérifiée.", "ok"))
    else:
        status = "invalid"
        steps.append(step(f"Vérification : g^H(m) ≡ y^r · r^s (mod p) avec la clé publique de {sender}",
                          "Les deux côtés sont différents.", "fail"))
    return data.decode("utf-8", errors="replace"), steps, signed_message(encrypted, status, sender)


# --- Ce que peut faire Eve -------------------------------------------------

def eve_read(eve_keys, packet, directory, stolen):
    payload, sender, recipient = packet["payload"], packet["from"], packet["to"]
    steps = []
    if not payload.get("encrypted"):
        text = payload.get("plaintext", "")
        steps.append(step("Le message circule en clair : lecture directe", None, "ok"))
        if payload.get("signature"):
            ok = _check_signature(directory[sender]["elgamal"], payload["signature"], text.encode())
            steps.append(step(f"Signature vérifiée avec la clé publique de {sender}",
                              "Valide." if ok else "Invalide.", "ok" if ok else "fail"))
        return {"success": True, "text": text, "steps": steps}

    blocks = _decode_blocks(payload["blocks"])
    if recipient in stolen:
        data, _ = eg.decrypt_bytes(blocks, stolen[recipient])
        steps.append(step(f"Déchiffrement avec la clé privée VOLÉE de {recipient}", None, "ok"))
        return {"success": True, "text": data.decode("utf-8", errors="replace"), "steps": steps}

    garbage, _ = eg.decrypt_bytes(blocks, eve_keys["x"])
    steps.append(step("Essai de déchiffrement avec ma propre clé privée",
                      "Résultat : " + garbage[:48].hex() + "… (charabia)", "fail"))
    steps.append(step(f"Retrouver x à partir de y = g^x mod p ({recipient})",
                      f"Logarithme discret dans un groupe de {eg.P_BITS} bits. Hors de portée.", "fail"))
    return {"success": False, "text": None, "steps": steps}


def eve_tamper(payload):
    payload = dict(payload)
    if payload.get("encrypted"):
        blocks = [list(b) for b in payload["blocks"]]
        c2 = int(blocks[0][1], 16)
        blocks[0][1] = f"{(c2 * 2) % eg.P:x}"
        payload["blocks"] = blocks
        return payload, "c₂ du premier bloc multiplié par 2 (El-Gamal est malléable : m devient 2·m mod p)."
    payload["plaintext"] = alter_text(payload.get("plaintext", ""))
    return payload, "Un caractère du texte en clair a été changé."


def eve_replace(eve_keys, packet, directory, text, signature_mode, stolen):
    payload = dict(packet["payload"])
    data = text.encode()
    sender, recipient = packet["from"], packet["to"]
    if payload.get("encrypted"):
        payload["blocks"] = _encode_blocks(eg.encrypt_bytes(data, _y(directory[recipient]["elgamal"])))
        note = f"Texte remplacé et rechiffré avec la clé publique de {recipient} (elle est publique)."
    else:
        payload["plaintext"] = text
        note = "Texte en clair remplacé."
    h = eg.hash_int(data)
    if signature_mode == "none":
        payload["signature"] = None
        note += " Signature supprimée."
    elif signature_mode == "eve":
        r, s = eg.sign(h, eve_keys["x"])
        payload["signature"] = {"r": f"{r:x}", "s": f"{s:x}"}
        note += " Signé avec la clé privée d'Eve."
    elif signature_mode == "stolen" and sender in stolen:
        r, s = eg.sign(h, stolen[sender])
        payload["signature"] = {"r": f"{r:x}", "s": f"{s:x}"}
        note += f" Signé avec la clé privée VOLÉE de {sender}."
    else:
        note += f" Signature d'origine de {sender} conservée."
    return payload, note


def find_reused_k(packets):
    """Paires de messages en clair, signés par la même personne avec le même r (donc le même k)."""
    seen, found = {}, []
    for p in packets:
        pl = p["original"]
        if p["scheme"] != ID or pl.get("encrypted") or not pl.get("signature"):
            continue
        key = (p["from"], pl["signature"]["r"])
        for other in seen.get(key, []):
            if other["original"]["plaintext"] != pl["plaintext"]:
                found.append({"victim": p["from"], "ids": [other["id"], p["id"]]})
                break
        seen.setdefault(key, []).append(p)
    return found


def recover_key(first, second, victim_public):
    a, b = first["original"], second["original"]
    h1, h2 = eg.hash_int(a["plaintext"].encode()), eg.hash_int(b["plaintext"].encode())
    s1, s2 = int(a["signature"]["s"], 16), int(b["signature"]["s"], 16)
    r = int(a["signature"]["r"], 16)
    steps = [
        step("Deux signatures avec le même r = g^k mod p : le même k a servi deux fois", f"r = {r:x}"),
        step("s₁ − s₂ ≡ (H(m₁) − H(m₂)) · k⁻¹ (mod p−1)",
             f"H(m₁) = {h1:x}\nH(m₂) = {h2:x}\ns₁ = {s1:x}\ns₂ = {s2:x}"),
    ]
    result = eg.recover_private_key(h1, s1, h2, s2, r, _y(victim_public))
    if result is None:
        steps.append(step("Résolution", "Pas de solution exploitable pour cette paire.", "fail"))
        return None, steps
    k, x = result
    steps.append(step("k = (H(m₁) − H(m₂)) / (s₁ − s₂) mod (p−1), vérifié par g^k = r", f"k = {k:x}", "ok"))
    steps.append(step("x = (H(m₁) − k·s₁) / r mod (p−1), vérifié par g^x = y", f"x = {x:x}", "ok"))
    return x, steps
