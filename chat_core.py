"""Logique réseau du client graphique (aucun code Tkinter ici).

Ce module reprend EXACTEMENT le protocole de client.py (mêmes fonctions de
common.py : handshake X25519 signé RSA, canal AES-GCM, défi/réponse HMAC).
Il sert uniquement à découper client.py en petites étapes réutilisables par
l'interface graphique, qui ne doit pas se bloquer sur des input().
"""
import json
import os
import socket

from client import fingerprint          # même calcul d'empreinte que client.py
from common import (auth_proof, derive_channel, exchange, hash_password,
                    new_ephemeral, recv_msg, send_msg, verify_handshake)

__all__ = ["ClientCore", "fingerprint", "pretty_fp", "trust_status",
           "remember_server", "local_ip"]


# ---------- Confiance dans le serveur (même fichier que client.py) ----------

def _known_file(host: str, port: int) -> str:
    return f"known_{host}_{port}.txt"


def trust_status(host: str, port: int, pem: bytes):
    """Retourne ("known" | "changed" | "new", empreinte)."""
    fp = fingerprint(pem)
    path = _known_file(host, port)
    if os.path.exists(path):
        with open(path) as f:
            return ("known" if f.read().strip() == fp else "changed"), fp
    return "new", fp


def remember_server(host: str, port: int, fp: str) -> None:
    with open(_known_file(host, port), "w") as f:
        f.write(fp)


def pretty_fp(fp: str) -> str:
    """Empreinte en 2 lignes de 8 groupes de 4 caractères (plus facile à comparer)."""
    groups = [fp[i:i + 4] for i in range(0, len(fp), 4)]
    return "\n".join(" ".join(groups[i:i + 8]) for i in range(0, len(groups), 8))


def local_ip() -> str:
    """Adresse IP de cette machine sur le réseau (aucun paquet n'est envoyé)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
    finally:
        s.close()


# ---------- Connexion chiffrée ----------

class ClientCore:
    """Une connexion client : connect -> handshake -> (confiance) -> login -> send/receive."""

    def __init__(self):
        self.sock = None
        self.channel = None

    def connect(self, host: str, port: int, timeout: float = 8) -> bytes:
        """Ouvre la connexion et retourne la clé publique PEM du serveur."""
        self.sock = socket.create_connection((host, port), timeout=timeout)
        return recv_msg(self.sock)

    def handshake(self, pem: bytes) -> None:
        """Échange de clés éphémères X25519 ; vérifie la signature RSA du serveur.

        Lève InvalidSignature si la signature est fausse. L'empreinte du
        serveur doit ensuite être contrôlée (trust_status) AVANT le login.
        """
        eph_private, client_eph = new_ephemeral()
        send_msg(self.sock, client_eph)
        reply = recv_msg(self.sock)
        server_eph, signature = reply[:32], reply[32:]
        verify_handshake(pem, client_eph, server_eph, signature)
        self.channel = derive_channel(exchange(eph_private, server_eph),
                                      client_eph, server_eph, "client")

    def login(self, user: str, password: str) -> str:
        """Défi/réponse (le mot de passe n'est jamais envoyé).
        Retourne la réponse du serveur : "OK", "DENIED" ou "LOCKED"."""
        self.channel.send(self.sock, json.dumps({"user": user}))
        info = json.loads(self.channel.recv(self.sock)[0])
        key = hash_password(password, bytes.fromhex(info["salt"]))
        proof = auth_proof(key, bytes.fromhex(info["challenge"]), self.channel.session_id)
        self.channel.send(self.sock, json.dumps({"proof": proof.hex()}))
        return self.channel.recv(self.sock)[0]

    def set_timeout(self, seconds) -> None:
        self.sock.settimeout(seconds)   # None = on attend sans limite les messages

    def send(self, text: str) -> bytes:
        """Chiffre et envoie ; retourne les octets chiffrés (pour l'affichage)."""
        return self.channel.send(self.sock, text)

    def receive(self):
        """Attend un message ; retourne (texte déchiffré, octets chiffrés)."""
        return self.channel.recv(self.sock)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()
            self.sock = None
