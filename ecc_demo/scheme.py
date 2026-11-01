"""Courbes elliptiques : Alice et Bob se mettent d'accord sur une clé (ECDH), chiffrent en AES-256-GCM
et peuvent signer en ECDSA. Courbe P-256 (secp256r1)."""
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common.codec import b64d, b64e, flip_byte, prop, sha256_hex, step

ID = "ecc"
LABEL = "Courbes elliptiques"
CURVE = ec.SECP256R1()
HKDF_INFO = b"demo ecdh p-256 / aes-256-gcm"


# --- Clés ------------------------------------------------------------------

def generate_keys():
    return ec.generate_private_key(CURVE)


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
    return [
        {"label": "Courbe", "value": "P-256 (secp256r1) : y² = x³ − 3x + b mod p, p ≈ 2²⁵⁶"},
        {"label": "Clé publique Q = d·G, coordonnée x", "value": f"{pub.x:x}"},
        {"label": "Clé publique Q = d·G, coordonnée y", "value": f"{pub.y:x}"},
        {"label": "Clé privée d (un nombre de 256 bits)", "value": f"{keys.private_numbers().private_value:x}",
         "secret": True},
    ]


def _derive(keys, peer_public):
    secret = keys.exchange(ec.ECDH(), _load(peer_public))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=HKDF_INFO).derive(secret)
    return secret, key


def peer_info(keys, peer_public):
    secret, key = _derive(keys, peer_public)
    return [
        {"label": "Secret partagé ECDH (coordonnée x de d·Q)", "value": secret.hex(), "secret": True},
        {"label": "Clé AES-256 dérivée (HKDF-SHA256)", "value": key.hex(), "secret": True},
    ]


def _aad(sender, recipient):
    # Lie le chiffré à l'expéditeur et au destinataire : on ne peut pas le rediriger sans le casser.
    return f"{sender}->{recipient}".encode()


# --- Envoi / réception -----------------------------------------------------

def send(keys, sender, recipient, recipient_public, text, options):
    data = text.encode()
    secret, key = _derive(keys, recipient_public)
    steps = [
        step(f"Secret ECDH calculé : ma clé privée × clé publique de {recipient}", secret.hex()),
        step("Clé AES-256 dérivée du secret (HKDF-SHA256)", key.hex()),
    ]
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, data, _aad(sender, recipient))
    payload = {"nonce": b64e(nonce), "ciphertext": b64e(ciphertext), "signature": None}
    steps.append(step("Chiffrement AES-256-GCM (nonce aléatoire de 96 bits, tag d'intégrité de 128 bits)",
                      payload["ciphertext"], "ok"))
    if options.get("sign", True):
        payload["signature"] = b64e(keys.sign(data, ec.ECDSA(hashes.SHA256())))
        steps.append(step("Signature ECDSA (SHA-256) avec ma clé privée", payload["signature"], "ok"))
    else:
        steps.append(step("Pas de signature ECDSA",
                          f"{recipient} saura que le message vient de moi, mais ne pourra pas le prouver à un tiers.",
                          "warn"))
    return payload, steps


def _verify(public, signature, data):
    try:
        _load(public).verify(b64d(signature), data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def _guarantees(sender, state):
    conf = prop("ok", f"Chiffré en AES-256-GCM avec une clé que seuls {sender} et moi pouvons calculer.")
    if state == "tampered":
        return {
            "confidentialite": conf,
            "integrite": prop("fail", "Le tag GCM ne correspond pas : le message a été modifié "
                                      "ou chiffré avec une autre clé."),
            "authenticite": prop("fail", f"Ce message n'a pas été chiffré avec la clé partagée avec {sender}."),
            "non_repudiation": prop("none", "Aucune preuve exploitable."),
        }
    integ = prop("ok", "Le tag GCM est valide : aucun bit n'a changé.")
    if state == "valid":
        auth = prop("ok", f"Signature ECDSA de {sender} valide.")
        nr = prop("ok", f"{sender} ne peut pas nier : la signature est vérifiable par n'importe qui.")
    elif state == "invalid":
        auth = prop("fail", f"La signature ne correspond pas à la clé publique de {sender}.")
        nr = prop("fail", "Aucune preuve exploitable.")
    else:
        auth = prop("ok", f"Implicite : seuls {sender} et moi connaissons la clé partagée.")
        nr = prop("none", f"Sans signature, {sender} pourrait prétendre que j'ai fabriqué ce message, "
                          f"puisque nous avons la même clé.")
    return {"confidentialite": conf, "integrite": integ, "authenticite": auth, "non_repudiation": nr}


def receive(keys, sender, recipient, sender_public, payload):
    secret, key = _derive(keys, sender_public)
    steps = [
        step(f"Secret ECDH calculé : ma clé privée × clé publique de {sender}", secret.hex()),
        step("Clé AES-256 dérivée (identique à celle de l'expéditeur)", key.hex()),
    ]
    try:
        data = AESGCM(key).decrypt(b64d(payload["nonce"]), b64d(payload["ciphertext"]), _aad(sender, recipient))
    except (InvalidTag, ValueError, KeyError):
        steps.append(step("Déchiffrement AES-256-GCM", "Tag invalide : message modifié ou mauvaise clé.", "fail"))
        return None, steps, _guarantees(sender, "tampered")
    steps.append(step("Déchiffrement AES-256-GCM et contrôle du tag", "Tag valide.", "ok"))

    signature = payload.get("signature")
    if signature is None:
        state = "absent"
        steps.append(step("Aucune signature ECDSA jointe", None, "warn"))
    elif _verify(sender_public, signature, data):
        state = "valid"
        steps.append(step(f"Signature ECDSA vérifiée avec la clé publique de {sender}", None, "ok"))
    else:
        state = "invalid"
        steps.append(step(f"Signature ECDSA vérifiée avec la clé publique de {sender}",
                          "La signature ne correspond pas.", "fail"))
    return data.decode("utf-8", errors="replace"), steps, _guarantees(sender, state)


# --- Ce que peut faire Eve -------------------------------------------------

def eve_read(eve_keys, packet, directory, stolen):
    payload, sender, recipient = packet["payload"], packet["from"], packet["to"]
    secret, key = _derive(eve_keys, directory[sender]["ecc"])
    steps = [
        step(f"J'ai vu passer les clés publiques de {sender} et {recipient}", None, "ok"),
        step(f"Secret calculé avec MA clé privée × clé publique de {sender}", secret.hex()),
    ]
    try:
        AESGCM(key).decrypt(b64d(payload["nonce"]), b64d(payload["ciphertext"]), _aad(sender, recipient))
    except (InvalidTag, ValueError):
        steps.append(step("Déchiffrement AES-256-GCM avec cette clé",
                          "Tag invalide : ce n'est pas la clé de " + sender + " et " + recipient + ".", "fail"))
    steps.append(step(f"Retrouver la clé privée de {sender} à partir de sa clé publique",
                      "Logarithme discret sur courbe elliptique : environ 2¹²⁸ opérations. Hors de portée.", "fail"))
    return {"success": False, "text": None, "steps": steps}


def eve_tamper(payload):
    payload = dict(payload)
    payload["ciphertext"] = b64e(flip_byte(b64d(payload["ciphertext"])))
    return payload, "Un octet du chiffré AES-GCM a été inversé."


def eve_replace(eve_keys, packet, directory, text, signature_mode, stolen):
    payload = dict(packet["payload"])
    data = text.encode()
    _, key = _derive(eve_keys, directory[packet["to"]]["ecc"])
    nonce = os.urandom(12)
    payload["nonce"] = b64e(nonce)
    payload["ciphertext"] = b64e(AESGCM(key).encrypt(nonce, data, _aad(packet["from"], packet["to"])))
    note = (f"Eve ne connaît pas la clé partagée entre {packet['from']} et {packet['to']} : "
            f"elle chiffre avec sa propre clé ECDH.")
    if signature_mode == "none":
        payload["signature"] = None
        note += " Signature supprimée."
    elif signature_mode == "eve":
        payload["signature"] = b64e(eve_keys.sign(data, ec.ECDSA(hashes.SHA256())))
        note += " Signé avec la clé privée d'Eve."
    else:
        note += " Signature d'origine conservée."
    return payload, note
