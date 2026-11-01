"""Petits utilitaires partagés : encodage, empreintes, étapes affichées dans l'interface."""
import base64
import hashlib
import re


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def step(label, value=None, state=None):
    """Une étape du traitement, affichée telle quelle. state : ok, fail, warn ou None."""
    return {"label": label, "value": value, "state": state}


def prop(state, text):
    """Une garantie de sécurité. state : ok, fail ou none (non assurée)."""
    return {"state": state, "text": text}


def flip_byte(data: bytes) -> bytes:
    """Inverse tous les bits d'un octet situé au milieu des données."""
    if not data:
        return b"\x00"
    i = len(data) // 2
    return data[:i] + bytes([data[i] ^ 0xFF]) + data[i + 1:]


def alter_text(text: str) -> str:
    """Modifie discrètement un texte : premier chiffre +1, sinon casse de la première lettre."""
    m = re.search(r"\d", text)
    if m:
        d = str((int(m.group()) + 1) % 10)
        return text[:m.start()] + d + text[m.end():]
    m = re.search(r"[^\W\d_]", text)
    if m:
        return text[:m.start()] + m.group().swapcase() + text[m.end():]
    return text + "."
