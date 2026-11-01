"""Les trois démonstrations, indépendantes, exposées avec la même interface."""
from ecc_demo import scheme as ecc
from elgamal_demo import scheme as elgamal
from rsa_demo import scheme as rsa

SCHEMES = {s.ID: s for s in (rsa, ecc, elgamal)}
