# Messagerie chiffrée : RSA, courbes elliptiques et El-Gamal

Trois démonstrations indépendantes, entre **deux personnes sur deux machines différentes**, avec
**Eve** qui contrôle le réseau et peut écouter (mode passif) ou intervenir (mode actif).

| Onglet | Ce qui est démontré | Mécanismes |
|---|---|---|
| RSA | Confidentialité, intégrité, authenticité, non-répudiation | RSA-2048 OAEP (chiffrement), SHA-256 + RSA-PSS (signature) |
| Courbes elliptiques | Comment Alice et Bob s'envoient des messages sécurisés | ECDH P-256 → HKDF → AES-256-GCM, signature ECDSA |
| El-Gamal | Sécurité de la transmission, signature numérique, authenticité, intégrité | Chiffrement et signature El-Gamal écrits à la main (groupe 2048 bits, RFC 3526) |

## Architecture

```
  Machine d'Alice              Machine d'Eve               Machine de Bob
 ┌────────────────┐         ┌─────────────────┐         ┌────────────────┐
 │ client.py      │  HTTP   │ relay.py        │  HTTP   │ client.py      │
 │ clés privées   │ ──────► │ voit tout passer│ ◄────── │ clés privées   │
 │ d'Alice        │         │ aucune clé      │         │ de Bob         │
 │ localhost:5001 │         │ privée d'Alice  │         │ localhost:5001 │
 └────────────────┘         │ ou de Bob       │         └────────────────┘
                            │ localhost:5000  │
                            └─────────────────┘
```

- Chaque participant lance `client.py` sur **sa** machine et choisit son nom dans le navigateur. Ses clés
  privées sont générées à ce moment dans ce processus et ne sont jamais envoyées. Son interface n'est accessible que depuis sa machine.
- Le relais (`relay.py`) joue le rôle du réseau. Seules les clés publiques et les messages chiffrés y passent.
  Son interface (celle d'Eve) n'est accessible que depuis la machine du relais.

## Installation

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt      # Windows : .venv\Scripts\pip install -r requirements.txt
```

## Lancer la démonstration

### Sur une seule machine (pour tester)

```bash
./demo_local.sh
```
Puis ouvrir : Eve http://localhost:5000, poste 1 http://localhost:5001, poste 2 http://localhost:5002.
Sur chaque poste, saisir son nom (Alice, Bob…) puis « Rejoindre ».

### Sur le réseau (trois machines)

1. **Machine d'Eve** :
   ```bash
   .venv/bin/python relay.py
   ```
   Le relais trouve tout seul l'adresse IP de la machine sur le réseau local et l'affiche :
   ```
     Adresse à donner aux participants :  http://192.168.1.208:5000
     Console d'Eve (sur cette machine)  :  http://localhost:5000
   ```
   La même adresse est affichée en haut de la console d'Eve, avec un bouton « Copier ».
2. **Machine de chaque participant** (Alice, Bob…) :
   ```bash
   .venv/bin/python client.py
   ```
   Ouvrir http://localhost:5001, saisir son nom et l'adresse donnée par Eve, puis « Rejoindre ».
   L'adresse est mémorisée pour la fois suivante. On peut aussi la passer directement :
   `client.py --relay http://192.168.1.208:5000`.

Le pare-feu de la machine d'Eve doit autoriser le port 5000 en entrée.

**Relais sous WSL2 :** en mode NAT, Linux a une adresse interne (172.x) que les autres machines ne voient pas.
Le relais le détecte, affiche l'adresse Windows à la place, et vérifie si Windows redirige le port vers WSL.
Si ce n'est pas le cas :
```bash
.venv/bin/python relay.py --wsl-forward
```
Windows demande une autorisation administrateur, puis crée la redirection et la règle de pare-feu.
L'adresse interne de WSL change à chaque redémarrage : le relais le signale, il suffit de relancer avec
`--wsl-forward`. Autre solution : le réseau « mirrored » (`networkingMode=mirrored` dans
`%UserProfile%\.wslconfig`, puis `wsl --shutdown`), qui rend toute redirection inutile.

## Scénarios à présenter

**RSA**
1. Alice envoie un message chiffré et signé. Bob voit les 4 garanties en vert. Eve clique sur
   « Essayer de déchiffrer » et échoue.
2. Alice décoche « Chiffrer ». Eve lit le message, mais Bob a toujours intégrité, authenticité et non-répudiation.
3. Eve passe en « Interception » et remplace le texte. Elle peut le rechiffrer avec la clé publique de Bob,
   mais pas refaire la signature d'Alice : Bob voit l'intégrité et l'authenticité en rouge.

**Courbes elliptiques**
1. Dans le panneau de droite, comparer le « secret partagé » d'Alice et celui de Bob : ils sont identiques,
   alors qu'il n'a jamais circulé.
2. Eve calcule un secret avec sa propre clé : il est différent, et le déchiffrement échoue.
3. Eve altère un octet : le tag GCM le détecte, le message est rejeté.
4. Sans signature ECDSA, l'authenticité reste assurée (seuls Alice et Bob ont la clé), mais pas la
   non-répudiation : Bob aurait pu fabriquer le message lui-même.

**El-Gamal**
1. Envoyer deux fois le même message chiffré : Eve voit deux chiffrés différents (chiffrement probabiliste).
2. Sans signature, Eve altère le chiffré : Bob reçoit du charabia sans alerte. El-Gamal seul ne garantit
   pas l'intégrité, c'est la signature qui le fait.
3. **Attaque :** Alice active « Même k (faille) », désactive « Chiffrer » et envoie deux messages signés
   différents. Eve voit la faille, retrouve la clé privée d'Alice, puis peut signer à sa place
   (Interception → Remplacer → « Signer avec la clé volée ») : Bob voit une signature valide.

## Organisation du code

```
common/        réseau (http.py), utilitaires (codec.py), bilan des garanties (guarantees.py)
rsa_demo/      scheme.py      : RSA avec la bibliothèque cryptography
ecc_demo/      scheme.py      : ECDH, AES-GCM, ECDSA avec la bibliothèque cryptography
elgamal_demo/  elgamal.py     : mathématiques d'El-Gamal écrites à la main
               scheme.py      : intégration dans la messagerie, attaque sur k
client.py      poste d'un participant
relay.py       relais réseau et interface d'Eve
web/           interface (HTML, CSS, JavaScript sans framework)
```

## Limites assumées (à mentionner pendant l'exposé)

- Les clés publiques sont distribuées par le relais. Dans la réalité, elles sont certifiées (certificats X.509,
  PKI) pour empêcher Eve de substituer sa propre clé.
- La signature est envoyée à côté du chiffré pour rester visible. En production, on la chiffre aussi,
  sinon Eve peut tester des hypothèses sur le contenu.
- Rien n'empêche Eve de rejouer un ancien message. Un vrai protocole ajoute un numéro de séquence ou un horodatage signé.
- Les clés sont régénérées à chaque démarrage et les messages ne sont pas sauvegardés.
