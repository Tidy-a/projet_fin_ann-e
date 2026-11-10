"""Client sécurisé (dialogue dans les deux sens) - version 2.
Usage : python client.py                    -> serveur sur cette machine (127.0.0.1:5000)
        python client.py 192.168.1.20       -> serveur sur une autre machine
        python client.py 192.168.1.20 5000  -> avec un port précis
"""
import json
import os
import socket
import sys
import threading

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes

from common import (PORT, aes_decrypt, aes_encrypt, ask_password, auth_proof,
                    derive_channel, exchange, hash_password, new_ephemeral,
                    recv_msg, send_msg, verify_handshake)


def parse_args():
    host, port = "127.0.0.1", PORT
    for arg in sys.argv[1:]:
        if arg.isdigit():
            port = int(arg)
        else:
            host = arg
    return host, port


def fingerprint(pem: bytes) -> str:
    d = hashes.Hash(hashes.SHA256())
    d.update(pem)
    return d.finalize().hex()


def verify_server(pem: bytes, host: str, port: int) -> bool:
    """Authentification du serveur : on mémorise son empreinte à la 1re connexion
    et on la compare aux suivantes (même principe que SSH).
    Le fichier dépend de l'adresse ET du port : known_<adresse>_<port>.txt"""
    known_file = f"known_{host}_{port}.txt"
    fp = fingerprint(pem)
    print(f"[*] Empreinte du serveur : {fp}")
    if os.path.exists(known_file):
        with open(known_file) as f:
            if f.read().strip() == fp:
                print("[*] Serveur reconnu (empreinte identique)")
                return True
        print("[!!!] ALERTE : l'empreinte du serveur a CHANGÉ ! Possible attaque (homme du milieu).")
        return False
    print("    Comparez cette empreinte avec celle affichée sur le serveur.")
    answer = input("Première connexion. Faire confiance à ce serveur ? (o/n) ")
    if answer.lower().startswith("o"):
        with open(known_file, "w") as f:
            f.write(fp)
        return True
    return False


def handshake(sock, host: str, port: int):
    """Retourne le canal chiffré, ou None si le serveur n'est pas de confiance."""
    pem = recv_msg(sock)

    # Échange de clés éphémères X25519 ; le serveur signe avec sa clé RSA.
    eph_private, client_eph = new_ephemeral()
    send_msg(sock, client_eph)
    reply = recv_msg(sock)
    server_eph, signature = reply[:32], reply[32:]
    verify_handshake(pem, client_eph, server_eph, signature)   # InvalidSignature si faux
    channel = derive_channel(exchange(eph_private, server_eph), client_eph, server_eph, "client")

    # On vérifie QUI est le serveur avant d'envoyer le moindre identifiant.
    if not verify_server(pem, host, port):
        return None
    return channel


def login(sock, channel) -> bool:
    """Le mot de passe n'est jamais envoyé : on répond à un défi aléatoire du serveur."""
    for _ in range(3):
        user = input("Utilisateur : ")
        password = ask_password("Mot de passe : ")
        channel.send(sock, json.dumps({"user": user}))
        info = json.loads(channel.recv(sock)[0])          # sel + défi
        key = hash_password(password, bytes.fromhex(info["salt"]))
        proof = auth_proof(key, bytes.fromhex(info["challenge"]), channel.session_id)
        channel.send(sock, json.dumps({"proof": proof.hex()}))
        reply = channel.recv(sock)[0]
        if reply == "OK":
            print("[*] Authentification réussie\n")
            return True
        if reply == "LOCKED":
            print("[!] Trop d'échecs : accès refusé.")
            return False
        print("[!] Identifiants incorrects, réessayez.")
    return False


def receiver(sock, channel, closing):
    """Écoute en permanence les messages du serveur (tourne en parallèle)."""
    try:
        while True:
            message, data = channel.recv(sock)
            print("\r" + " " * 30 + "\r", end="")          # efface le 'Vous >' en attente
            print(f"Serveur > [chiffré reçu] {data.hex()[:48]}...")
            print(f"Serveur > {message}   (déchiffré)")
            print("Vous > ", end="", flush=True)
    except (ConnectionError, OSError, InvalidTag):
        if not closing.is_set():
            print("\n[!] Connexion fermée par le serveur (ou message altéré/rejoué).")
            os._exit(0)


def main():
    host, port = parse_args()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(15)
            sock.connect((host, port))
            print(f"[*] Connecté à {host}:{port}")

            # 1) HANDSHAKE
            channel = handshake(sock, host, port)
            if channel is None:
                print("Connexion annulée.")
                return
            print("[*] Handshake terminé : canal chiffré établi (X25519 + AES-256-GCM)")

            # 2) AUTHENTIFICATION
            sock.settimeout(300)
            if not login(sock, channel):
                return
            sock.settimeout(None)

            # 3) DIALOGUE : un thread écoute le serveur, la boucle ci-dessous envoie
            closing = threading.Event()
            threading.Thread(target=receiver, args=(sock, channel, closing), daemon=True).start()
            print("Tapez vos messages ('quit' pour quitter).")
            while True:
                try:
                    message = input("Vous > ")
                except EOFError:
                    message = "quit"
                if not message:
                    continue
                channel.send(sock, message)
                if message.lower() == "quit":
                    closing.set()
                    break
    except InvalidSignature:
        print("[!!!] Signature du serveur INVALIDE : le serveur est peut-être usurpé. Connexion coupée.")
    except ConnectionError as e:
        print(f"[!] Connexion fermée par le serveur ({e}). "
              "Si vous avez fait trop d'erreurs de mot de passe, attendez une minute.")
    except (OSError, ValueError, InvalidTag) as e:
        print(f"[!] Erreur de connexion : {e}")


if __name__ == "__main__":
    main()
