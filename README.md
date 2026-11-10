# Chat chiffré client-serveur (Sujet 8) – version 2 : terminal + interface Tkinter

Mini serveur TCP et client avec :
- **handshake** : échange de clés éphémères X25519 (Diffie-Hellman), **signées par la clé RSA-2048 du serveur** ;
- **chiffrement des messages** : AES-256-GCM (confidentialité + intégrité), une clé par sens, message numéroté ;
- **authentification** : défi/réponse HMAC, le mot de passe n'est jamais envoyé (stocké en PBKDF2 + sel) ;
- **identité du serveur** : signature RSA + empreinte SHA-256 mémorisée à la 1re connexion (comme SSH) ;
- **protections** : anti-rejeu, limite de taille, délais d'attente, blocage après trop d'échecs.

## 1. Outils nécessaires (sur CHAQUE machine)

| Outil | Pourquoi | Installation |
|---|---|---|
| Python 3.9 ou plus | exécuter le projet | https://www.python.org (cocher « Add Python to PATH » sous Windows) |
| Bibliothèque `cryptography` | RSA et AES | `pip install -r requirements.txt` |
| Tkinter | interface graphique | inclus avec Python sous Windows et macOS. Linux : `sudo apt install python3-tk` |

Vérification : `python --version` puis `python -c "import tkinter, cryptography; print('OK')"`
(sous Linux/macOS, utilisez `python3` à la place de `python`).

## 2. Contenu du projet

| Fichier | Rôle |
|---|---|
| `common.py` | envoi/réception (taille en préfixe), AES-GCM, hash des mots de passe |
| `server.py` / `client.py` | version **terminal** (inchangée) |
| `gui_server.py` / `gui_client.py` | version **interface graphique** (nouveau) |
| `ui_theme.py` | apparence commune des interfaces : couleurs, bulles de discussion, fenêtres (aucune crypto) |
| `chat_core.py` | étapes réseau du client graphique (sans Tkinter) |
| `test_securite.py` | 19 tests automatiques des protections (sans interface) |
| `create_user.py` | crée un utilisateur en terminal |
| `pirate.py` | démo : un attaquant modifie ou rejoue un message, le serveur le détecte |
| `serveur_clair.py` / `client_clair.py` | démo Wireshark : même chat SANS chiffrement |

Les versions terminal et graphique sont **interchangeables** : `gui_client.py`
fonctionne avec `server.py`, et `client.py` fonctionne avec `gui_server.py`.
Toute la cryptographie est dans `common.py` ; les fichiers `gui_*.py` ne contiennent aucune cryptographie.
**Attention : la version 2 n'est pas compatible avec l'ancienne** (le protocole a changé) : le serveur et
les clients doivent tous utiliser ce dossier. Le fichier `users.json` de l'ancienne version reste valable.

## 3. Utilisation sur UNE seule machine (test rapide)

1. `pip install -r requirements.txt`
2. Terminal 1 : `python gui_server.py` → cliquer sur **Ajouter un utilisateur** (ex. `alice` / `motdepasse`)
3. Terminal 2 : `python gui_client.py` → adresse `127.0.0.1`, port `5000`, identifiants → **Se connecter**
4. À la 1re connexion, une fenêtre affiche l'empreinte du serveur : comparer avec celle du serveur, puis **Oui**.
5. Écrire un message dans le client → il apparaît dans le serveur. Écrire dans le serveur (« Envoyer à tous ») → il apparaît dans le client.

## 4. Utilisation sur DEUX machines (pas à pas)

**Pré-requis** : les deux machines sont sur le même réseau (même Wi-Fi / même box ou partage de connexion). Les Wi-Fi publics ou d'école isolent parfois les appareils entre eux : si ça ne marche pas, utilisez le partage de connexion d'un téléphone.

### Machine A – le SERVEUR
1. Copier le dossier du projet, installer Python puis `pip install -r requirements.txt`.
2. Lancer : `python gui_server.py`
   - **Windows** : une fenêtre du pare-feu s'ouvre → cocher *Réseaux privés* → **Autoriser l'accès**.
   - Si elle ne s'ouvre pas : Pare-feu Windows Defender → Paramètres avancés → Règles de trafic entrant → Nouvelle règle → Port → TCP **5000** → Autoriser.
3. Dans la fenêtre, noter :
   - l'**adresse IP** affichée (ex. `192.168.1.20`) ;
   - l'**empreinte SHA-256** (les 2 lignes de caractères).
4. Cliquer sur **Ajouter un utilisateur** et créer un compte (nom + mot de passe).
   (Ou en terminal : `python create_user.py`.)

### Machine B – le CLIENT
1. Copier le dossier du projet, installer Python puis `pip install -r requirements.txt`.
   Copiez le dossier **tel qu'il est dans le zip d'origine** (avant d'avoir lancé le serveur). Ne copiez JAMAIS :
   `server_key.pem` (clé privée du serveur), `users.json` (comptes), `known_*.txt` (empreintes mémorisées) ni `__pycache__`.
   Ces fichiers n'existent qu'après un lancement. Fichiers réellement nécessaires au client :
   `common.py`, `client.py`, `chat_core.py`, `gui_client.py`, `ui_theme.py`, `requirements.txt`.
2. Lancer : `python gui_client.py`
3. Remplir : **adresse IP du serveur** (celle notée en A.3), **port** `5000`, **utilisateur** et **mot de passe** → **Se connecter**.
4. Fenêtre « Première connexion » : **comparer l'empreinte avec celle affichée sur la machine A**
   (lire à voix haute ou envoyer par un autre canal). Si elle est identique → **Oui**.
   C'est cette comparaison qui protège contre un faux serveur.

### Répondre à tous les clients ou à un seul

Dans la fenêtre du serveur, la liste « Clients connectés » commence par **Tous les clients** (sélectionné par défaut).
- **Rien d'autre sélectionné** : le bouton affiche « Envoyer à tous » et le message part à tous les clients.
- **Cliquer sur un client** (par exemple Alice) : le bouton devient « Envoyer à Alice » et le message part **à elle seule**,
  chiffré avec sa propre clé. Les autres clients ne reçoivent rien.
- Pour revenir à tous : cliquer sur « Tous les clients ».
- Les messages reçus sont affichés dans une seule fenêtre, chacun avec le nom de l'utilisateur et son heure.

Version terminal (`server.py`) : tapez `bonjour` pour répondre à tous, ou `@alice bonjour` pour répondre à Alice seulement.

### Tester l'envoi / réception
1. Client : écrire « bonjour » → Entrée. Le serveur affiche `Client (alice) > bonjour (déchiffré)`.
2. Serveur : écrire « bien reçu » → **Envoyer à tous** (ou sélectionner un client pour lui répondre à lui seul). Le client affiche `Serveur > bien reçu`.
3. Cocher « Afficher les messages chiffrés » dans le client pour montrer le texte chiffré (hexadécimal) à côté du texte clair.
4. Quitter : écrire `quit` côté client ou fermer la fenêtre.

### Si ça ne marche pas
| Message / symptôme | Cause probable | Solution |
|---|---|---|
| « Impossible de joindre le serveur » / délai dépassé | pare-feu, mauvaise IP, réseaux différents, serveur non lancé | vérifier l'IP, autoriser le port 5000, même réseau ; test : `ping <IP>` |
| « Connection refused » | serveur non lancé ou mauvais port | lancer `gui_server.py`, vérifier le port |
| « ALERTE : l'empreinte a CHANGÉ » | le serveur a une nouvelle clé (fichier `server_key.pem` supprimé) ou attaque | si c'est normal : supprimer `known_<IP>_<port>.txt` côté client |
| « Connexion fermée par le serveur… trop d'erreurs de mot de passe » | 6 échecs en moins d'une minute depuis la même IP | attendre une minute |
| Connexion fermée dès le début avec une ancienne version | protocole v1 ≠ v2 | utiliser la même version partout |
| « Identifiants incorrects » | mauvais nom / mot de passe | recréer l'utilisateur avec « Ajouter un utilisateur » |
| `ModuleNotFoundError: cryptography` | bibliothèque absente | `pip install cryptography` |
| `ModuleNotFoundError: tkinter` | Tkinter absent (Linux) | `sudo apt install python3-tk` |
| « Port indisponible » | un autre serveur tourne déjà | le fermer, ou `python gui_server.py 6000` (et mettre 6000 côté client) |

Adresse IP d'une machine : Windows `ipconfig` (IPv4) · Linux `hostname -I` · macOS `ipconfig getifaddr en0`.

## 5. Protocole (version 2)

```
   Client                                              Serveur
     | <----------- clé publique RSA (identité) ---------- |
     | -- clé éphémère X25519 du client ------------------> |
     | <-- clé éphémère X25519 du serveur + SIGNATURE RSA --|   (signature sur les 2 clés éphémères)
     |  vérifie la signature, calcule le secret partagé     |  calcule le même secret partagé
     |  HKDF -> clé client->serveur, clé serveur->client    |  HKDF -> mêmes clés
     |  vérifie l'empreinte (confiance 1re connexion)       |
     | == tout ce qui suit est chiffré AES-256-GCM, numéroté ==
     | -- nom d'utilisateur ------------------------------> |
     | <-- sel + défi aléatoire --------------------------- |
     | -- HMAC(PBKDF2(mot de passe, sel), défi + session) -> |
     | <-- OK / DENIED / LOCKED --------------------------- |
     | <=============== messages du chat =================> |
```

## 6. Ce qui a changé par rapport à la version 1 (sécurité)

| Problème corrigé | Solution |
|---|---|
| Même clé AES dans les deux sens : un message du client pouvait être renvoyé au client comme s'il venait du serveur | **Deux clés** (HKDF), une par sens |
| Rejeu : un message capturé pouvait être renvoyé | **Numéro de message** dans les données authentifiées GCM (suppression et réordonnancement détectés aussi) |
| Mot de passe envoyé au serveur | **Défi/réponse HMAC** liée à la session : le mot de passe ne circule jamais |
| Force brute par reconnexions | **Pause d'1 s** après chaque échec + **blocage de l'IP** (6 échecs / 60 s) |
| Message de 4 Go annoncé, connexion muette | **Taille max 64 Ko**, **délais d'attente** (15 s handshake, 5 min login) |
| Un fichier d'empreinte par adresse seulement ; comptes devinables par le temps de réponse | `known_<adresse>_<port>.txt` ; **faux sel stable** pour les utilisateurs inconnus |
| Une fuite de la clé RSA du serveur déchiffrait les anciennes conversations | **Forward secrecy** : X25519 éphémère (RSA ne fait plus que signer) |

**Limites restantes (à citer à l'oral)** : pas de certificats (confiance à la 1re connexion + comparaison
de l'empreinte) ; `users.json` contient un hash qui sert aussi de secret pour le défi/réponse : il doit rester
confidentiel (un protocole comme SCRAM ou OPAQUE corrigerait cela) ; la clé privée `server_key.pem` n'est
pas protégée par mot de passe ; un attaquant actif peut toujours couper la connexion.

Tests : `python -m unittest -v test_securite` (19 tests : signature, anti-rejeu, réflexion, taille, blocage…).

## 7. Démonstrations (soutenance)

- **Chiffrement vs clair, avec Wireshark (deux machines)** :
  1. Machine A : `python serveur_clair.py` (port 5001, autoriser le port dans le pare-feu).
  2. Machine A : lancer Wireshark, choisir l'interface Wi-Fi, filtre d'affichage `tcp.port == 5001`, cliquer sur « Démarrer la capture ».
  3. Machine B : `python client_clair.py <IP de A>` (utilisateur `alice`, mot de passe `motdepasse123`), envoyer quelques messages, puis `quit`.
  4. Wireshark : clic droit sur un paquet → Suivre → Flux TCP : le mot de passe et les messages sont lisibles.
  5. Recommencer avec le chat chiffré (`python gui_server.py` / `python gui_client.py`, port 5000, filtre `tcp.port == 5000`) :
     le flux TCP ne contient que des octets illisibles.
- **Attaque par modification** : `python server.py`, `python pirate.py`, `python client.py 5002`. Le 2e message du chat est modifié en route, le serveur affiche l'alerte (échec GCM).
- **Attaque par rejeu** : même chose avec `python pirate.py rejeu` : le message est envoyé deux fois, la copie est refusée (numéro de message déjà utilisé).
- **Faux serveur** : supprimer `server_key.pem` côté serveur, relancer → le client affiche l'alerte d'empreinte.

## 8. Remise à zéro
Supprimer : `known_*.txt` (client), `server_key.pem` et `users.json` (serveur).
# projet_fin_ann-e
