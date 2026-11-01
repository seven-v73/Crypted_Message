"""Bilan des garanties de sécurité pour un schéma « chiffrement asymétrique + signature » (RSA, El-Gamal)."""
from common.codec import prop


def signed_message(encrypted, signature, sender):
    """signature : valid, invalid, absent ou tampered (chiffré illisible)."""
    if encrypted:
        conf = prop("ok", "Chiffré avec ma clé publique : personne d'autre ne peut le lire.")
    else:
        conf = prop("none", "Envoyé en clair : toute personne sur le réseau a pu le lire.")

    if signature == "valid":
        return {
            "confidentialite": conf,
            "integrite": prop("ok", "L'empreinte recalculée correspond à celle qui a été signée : rien n'a changé."),
            "authenticite": prop("ok", f"Seule la clé privée de {sender} peut produire cette signature."),
            "non_repudiation": prop("ok", f"{sender} ne peut pas nier l'envoi : n'importe qui peut vérifier "
                                          f"la signature avec sa clé publique."),
        }
    if signature == "invalid":
        return {
            "confidentialite": conf,
            "integrite": prop("fail", "La signature ne correspond pas : le message a été modifié."),
            "authenticite": prop("fail", f"Rien ne prouve que ce message vienne de {sender}."),
            "non_repudiation": prop("fail", "Aucune preuve exploitable."),
        }
    if signature == "tampered":
        return {
            "confidentialite": conf,
            "integrite": prop("fail", "Le chiffré a été altéré pendant le transport."),
            "authenticite": prop("fail", "Impossible de vérifier l'expéditeur d'un message illisible."),
            "non_repudiation": prop("none", "Aucune preuve exploitable."),
        }
    return {
        "confidentialite": conf,
        "integrite": prop("none", "Pas de signature : une modification ne serait pas détectée."),
        "authenticite": prop("none", f"Rien ne prouve que {sender} soit l'auteur."),
        "non_repudiation": prop("none", f"{sender} pourrait nier avoir envoyé ce message."),
    }
