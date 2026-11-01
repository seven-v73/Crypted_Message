"""El-Gamal implémenté à la main : chiffrement, signature, et attaque par réutilisation de k.

Paramètres publics : le nombre premier « sûr » de 2048 bits du groupe 14 de la RFC 3526
(p = 2q + 1 avec q premier) et le générateur g = 2.
"""
import hashlib
import secrets
from math import gcd

P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
G = 2
P_BITS = P.bit_length()
# Un bloc de message doit être un entier < p. On préfixe chaque bloc par 0x01 pour garder les zéros de tête.
BLOCK_BYTES = 200


def generate_keys():
    """Clé privée x aléatoire, clé publique y = g^x mod p."""
    x = secrets.randbelow(P - 3) + 2
    return x, pow(G, x, P)


def hash_int(data: bytes) -> int:
    """H(m) : SHA-256 du message, vu comme un entier modulo p − 1."""
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % (P - 1)


# --- Chiffrement -----------------------------------------------------------

def encrypt_int(m, y):
    """c1 = g^k mod p, c2 = m · y^k mod p, avec un k neuf à chaque appel."""
    k = secrets.randbelow(P - 3) + 2
    return pow(G, k, P), (m * pow(y, k, P)) % P


def decrypt_int(c1, c2, x):
    """m = c2 · (c1^x)^-1 mod p."""
    shared = pow(c1, x, P)
    return (c2 * pow(shared, -1, P)) % P


def encrypt_bytes(data, y):
    chunks = [data[i:i + BLOCK_BYTES] for i in range(0, len(data), BLOCK_BYTES)] or [b""]
    return [encrypt_int(int.from_bytes(b"\x01" + c, "big"), y) for c in chunks]


def decrypt_bytes(blocks, x):
    """Renvoie (données, format_correct). Un chiffré modifié donne du charabia, sans erreur :
    El-Gamal seul ne protège pas l'intégrité."""
    out, well_formed = b"", True
    for c1, c2 in blocks:
        m = decrypt_int(c1, c2, x)
        raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
        if raw[:1] == b"\x01":
            raw = raw[1:]
        else:
            well_formed = False
        out += raw
    return out, well_formed


# --- Signature -------------------------------------------------------------

def random_k():
    """k aléatoire inversible modulo p − 1."""
    while True:
        k = secrets.randbelow(P - 3) + 2
        if gcd(k, P - 1) == 1:
            return k


def sign(h, x, k=None):
    """r = g^k mod p, s = (H(m) − x·r) · k^-1 mod (p − 1)."""
    while True:
        kk = k if k is not None else random_k()
        r = pow(G, kk, P)
        s = ((h - x * r) * pow(kk, -1, P - 1)) % (P - 1)
        if s != 0 or k is not None:
            return r, s


def verify(h, r, s, y):
    """Valide si g^H(m) ≡ y^r · r^s (mod p)."""
    if not (0 < r < P and 0 < s < P - 1):
        return False
    return pow(G, h, P) == (pow(y, r, P) * pow(r, s, P)) % P


# --- Attaque : même k pour deux signatures ---------------------------------

def _solve_linear(a, b, n, limit=1024):
    """Toutes les solutions de a·z ≡ b (mod n), s'il y en a un nombre raisonnable."""
    d = gcd(a % n, n)
    if b % d or d > limit:
        return []
    a, b, m = a // d, b // d, n // d
    z0 = (b * pow(a, -1, m)) % m
    return [z0 + i * m for i in range(d)]


def recover_private_key(h1, s1, h2, s2, r, y):
    """Deux signatures (r, s1) et (r, s2) avec le même r, donc le même k :
        s1 − s2 ≡ (h1 − h2) · k^-1     ⇒  k = (h1 − h2) / (s1 − s2)  mod (p − 1)
        x · r ≡ h1 − k · s1             ⇒  x = (h1 − k·s1) / r        mod (p − 1)
    Les divisions se font en résolvant des congruences linéaires (p − 1 n'est pas premier) ;
    on garde la solution qui vérifie g^k = r puis g^x = y."""
    n = P - 1
    for k in _solve_linear(s1 - s2, h1 - h2, n):
        if pow(G, k, P) != r:
            continue
        for x in _solve_linear(r, h1 - k * s1, n):
            if pow(G, x, P) == y:
                return k, x
    return None
