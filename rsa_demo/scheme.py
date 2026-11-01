"""RSA : confidentialité (RSA-OAEP), intégrité, authenticité et non-répudiation (signature RSA-PSS)."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from common.codec import alter_text, b64d, b64e, flip_byte, sha256_hex, step
from common.guarantees import signed_message

ID = "rsa"
LABEL = "RSA"
KEY_BITS = 2048
# OAEP avec SHA-256 : au plus k − 2·hLen − 2 = 256 − 64 − 2 = 190 octets par bloc
BLOCK_BYTES = KEY_BITS // 8 - 2 * 32 - 2

_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


# --- Clés ------------------------------------------------------------------

def generate_keys():
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)


def export_public(keys):
    pem = keys.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"pem": pem.decode()}


def _load(public):
    return serialization.load_pem_public_key(public["pem"].encode())


def fingerprint(public):
    return sha256_hex(public["pem"].encode())[:16]


def key_info(keys):
    pub = keys.public_key().public_numbers()
    priv = keys.private_numbers()
    return [
        {"label": f"Module n = p × q ({KEY_BITS} bits, public)", "value": f"{pub.n:x}"},
        {"label": "Exposant e (public)", "value": str(pub.e)},
        {"label": "Exposant d (privé)", "value": f"{priv.d:x}", "secret": True},
        {"label": "Facteurs p et q (privés)", "value": f"p = {priv.p:x}\n\nq = {priv.q:x}", "secret": True},
    ]


def peer_info(keys, peer_public):
    return []


# --- Envoi / réception -----------------------------------------------------

def _encrypt(public, data):
    pub = _load(public)
    chunks = [data[i:i + BLOCK_BYTES] for i in range(0, len(data), BLOCK_BYTES)] or [b""]
    return [b64e(pub.encrypt(c, _OAEP)) for c in chunks]


def send(keys, sender, recipient, recipient_public, text, options):
    data = text.encode()
    encrypted = bool(options.get("encrypt", True))
    payload = {"encrypted": encrypted, "signature": None}
    steps = [step("Empreinte SHA-256 du message", sha256_hex(data))]

    if options.get("sign", True):
        payload["signature"] = b64e(keys.sign(data, _PSS, hashes.SHA256()))
        steps.append(step("Signature RSA-PSS de l'empreinte avec ma clé privée", payload["signature"], "ok"))
    else:
        steps.append(step("Pas de signature", "Le destinataire ne pourra vérifier ni l'auteur ni l'intégrité.", "warn"))

    if encrypted:
        payload["blocks"] = _encrypt(recipient_public, data)
        n = len(payload["blocks"])
        steps.append(step(f"Chiffrement RSA-OAEP avec la clé publique de {recipient} "
                          f"({n} bloc{'s' if n > 1 else ''} de {BLOCK_BYTES} octets max)",
                          "\n\n".join(payload["blocks"]), "ok"))
    else:
        payload["plaintext"] = text
        steps.append(step("Envoi en clair", "Toute personne sur le réseau pourra lire ce message.", "warn"))
    return payload, steps


def _verify(public, signature, data):
    try:
        _load(public).verify(b64d(signature), data, _PSS, hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


def receive(keys, sender, recipient, sender_public, payload):
    steps = []
    encrypted = payload.get("encrypted")
    if encrypted:
        try:
            data = b"".join(keys.decrypt(b64d(b), _OAEP) for b in payload["blocks"])
        except (ValueError, KeyError):
            steps.append(step("Déchiffrement RSA-OAEP avec ma clé privée",
                              "Le chiffré est invalide : il a été modifié en route.", "fail"))
            return None, steps, signed_message(True, "tampered", sender)
        steps.append(step("Déchiffrement RSA-OAEP avec ma clé privée", None, "ok"))
    else:
        data = payload.get("plaintext", "").encode()
        steps.append(step("Message reçu en clair", "Il a pu être lu par n'importe qui en chemin.", "warn"))

    steps.append(step("Empreinte SHA-256 recalculée", sha256_hex(data)))
    signature = payload.get("signature")
    if signature is None:
        status = "absent"
        steps.append(step("Aucune signature jointe", None, "warn"))
    elif _verify(sender_public, signature, data):
        status = "valid"
        steps.append(step(f"Signature vérifiée avec la clé publique de {sender}",
                          "L'empreinte signée correspond à l'empreinte recalculée.", "ok"))
    else:
        status = "invalid"
        steps.append(step(f"Signature vérifiée avec la clé publique de {sender}",
                          "La signature ne correspond pas au message reçu.", "fail"))
    return data.decode("utf-8", errors="replace"), steps, signed_message(encrypted, status, sender)


# --- Ce que peut faire Eve -------------------------------------------------

def eve_read(eve_keys, packet, directory, stolen):
    payload, sender, recipient = packet["payload"], packet["from"], packet["to"]
    steps = []
    if not payload.get("encrypted"):
        text = payload.get("plaintext", "")
        steps.append(step("Le message circule en clair : lecture directe", None, "ok"))
        if payload.get("signature"):
            ok = _verify(directory[sender]["rsa"], payload["signature"], text.encode())
            steps.append(step(f"Signature vérifiée avec la clé publique de {sender}",
                              "Valide : tout le monde peut vérifier qu'elle vient de " + sender
                              if ok else "Invalide.", "ok" if ok else "fail"))
        return {"success": True, "text": text, "steps": steps}

    try:
        b"".join(eve_keys.decrypt(b64d(b), _OAEP) for b in payload["blocks"])
    except ValueError:
        steps.append(step("Essai de déchiffrement avec ma propre clé privée",
                          f"Échec : le message a été chiffré pour la clé publique de {recipient}.", "fail"))
    n = _load(directory[recipient]["rsa"]).public_numbers().n
    steps.append(step(f"Retrouver la clé privée de {recipient}",
                      f"Il faudrait factoriser n, un nombre de {len(str(n))} chiffres. Hors de portée.", "fail"))
    return {"success": False, "text": None, "steps": steps}


def eve_tamper(payload):
    payload = dict(payload)
    if payload.get("encrypted"):
        blocks = list(payload["blocks"])
        blocks[0] = b64e(flip_byte(b64d(blocks[0])))
        payload["blocks"] = blocks
        return payload, "Un octet du premier bloc chiffré a été inversé."
    payload["plaintext"] = alter_text(payload.get("plaintext", ""))
    return payload, "Un caractère du texte en clair a été changé."


def eve_replace(eve_keys, packet, directory, text, signature_mode, stolen):
    payload = dict(packet["payload"])
    data = text.encode()
    if payload.get("encrypted"):
        payload["blocks"] = _encrypt(directory[packet["to"]]["rsa"], data)
        note = f"Texte remplacé et rechiffré avec la clé publique de {packet['to']} (elle est publique)."
    else:
        payload["plaintext"] = text
        note = "Texte en clair remplacé."
    if signature_mode == "none":
        payload["signature"] = None
        note += " Signature supprimée."
    elif signature_mode == "eve":
        payload["signature"] = b64e(eve_keys.sign(data, _PSS, hashes.SHA256()))
        note += " Signé avec la clé privée d'Eve."
    else:
        note += f" Signature d'origine de {packet['from']} conservée."
    return payload, note
