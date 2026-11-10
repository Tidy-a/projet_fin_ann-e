"""Fonctions communes au client et au serveur (version 2, renforcée)."""
import getpass
import hashlib
import hmac
import os
import struct
import sys
import threading

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HOST = "127.0.0.1"
PORT = 5000
MAX_MSG = 64 * 1024        # taille maximale d'un message (protège la mémoire du serveur)


# ---------- Envoi / réception de messages (avec taille en préfixe) ----------
# TCP est un flux : on ne sait pas où un message s'arrête.
# Solution : on envoie d'abord 4 octets contenant la taille, puis le message.

def send_msg(sock, data: bytes):
    if len(data) > MAX_MSG:
        raise ValueError("Message trop grand")
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connexion fermée")
        buf += chunk
    return buf


def recv_msg(sock) -> bytes:
    size = struct.unpack(">I", _recv_exact(sock, 4))[0]
    if size > MAX_MSG:      # sans cette limite, un attaquant pourrait annoncer 4 Go
        raise ConnectionError("Message trop grand : connexion refusée")
    return _recv_exact(sock, size)


# ---------- Chiffrement AES-256-GCM ----------
# GCM chiffre ET vérifie l'intégrité : si quelqu'un modifie le message,
# le déchiffrement échoue (exception InvalidTag).
# "aad" = données authentifiées (non chiffrées) : on y met le numéro du message.

def aes_encrypt(key: bytes, plaintext: str, aad: bytes = None) -> bytes:
    nonce = os.urandom(12)  # valeur aléatoire unique par message
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return nonce + ciphertext


def aes_decrypt(key: bytes, data: bytes, aad: bytes = None) -> str:
    nonce, ciphertext = data[:12], data[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad).decode("utf-8")


# ---------- Handshake : X25519 éphémère signé par la clé RSA du serveur ----------
# 1. Chacun crée une paire de clés X25519 JETABLE (éphémère) et envoie sa clé publique.
# 2. Le serveur SIGNE (RSA-PSS) les deux clés éphémères avec sa clé RSA : le client
#    vérifie la signature -> il sait que c'est bien le serveur (identité = empreinte RSA).
# 3. Les deux calculent le même secret partagé (Diffie-Hellman) sans jamais l'envoyer.
# Les clés éphémères étant jetées après la session, même si la clé RSA du serveur
# fuite plus tard, les anciennes conversations restent illisibles (forward secrecy).

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)


def new_ephemeral():
    """Retourne (clé privée jetable, clé publique en 32 octets)."""
    private = x25519.X25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw)
    return private, public


def exchange(private, peer_public: bytes) -> bytes:
    """Secret partagé Diffie-Hellman (lève ValueError si la clé reçue est invalide)."""
    if len(peer_public) != 32:
        raise ValueError("clé éphémère invalide")
    return private.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))


def _transcript(client_eph: bytes, server_eph: bytes) -> bytes:
    return b"chat-v2 handshake|" + client_eph + server_eph


def sign_handshake(rsa_private_key, client_eph: bytes, server_eph: bytes) -> bytes:
    return rsa_private_key.sign(_transcript(client_eph, server_eph), _PSS, hashes.SHA256())


def verify_handshake(server_pem: bytes, client_eph: bytes, server_eph: bytes, signature: bytes):
    """Lève cryptography.exceptions.InvalidSignature si la signature est fausse."""
    serialization.load_pem_public_key(server_pem).verify(
        signature, _transcript(client_eph, server_eph), _PSS, hashes.SHA256())


# ---------- Canal chiffré : une clé par sens + numéro de message ----------

class Channel:
    """Canal AES-GCM d'une connexion.

    - Deux clés différentes (client->serveur et serveur->client) : un message
      du client ne peut pas être renvoyé au client comme s'il venait du serveur.
    - Un compteur dans les données authentifiées : un message rejoué, supprimé
      ou réordonné fait échouer le déchiffrement (InvalidTag).
    - Le verrou garantit que l'ordre des compteurs = l'ordre d'envoi, même si
      plusieurs threads envoient en même temps.
    """

    def __init__(self, send_key: bytes, recv_key: bytes, session_id: bytes):
        self._send_key = send_key
        self._recv_key = recv_key
        self.session_id = session_id      # identifiant unique de CETTE session
        self._tx = 0
        self._rx = 0
        self._lock = threading.Lock()

    def send(self, sock, text: str) -> bytes:
        """Chiffre et envoie ; retourne les octets chiffrés (pour l'affichage)."""
        with self._lock:
            data = aes_encrypt(self._send_key, text, struct.pack(">Q", self._tx))
            send_msg(sock, data)
            self._tx += 1
        return data

    def recv(self, sock):
        """Reçoit et déchiffre ; retourne (texte, octets chiffrés)."""
        data = recv_msg(sock)
        text = aes_decrypt(self._recv_key, data, struct.pack(">Q", self._rx))
        self._rx += 1
        return text, data


def derive_channel(shared: bytes, client_eph: bytes, server_eph: bytes, role: str) -> Channel:
    """Dérive les clés de session avec HKDF. role = "client" ou "server"."""
    okm = HKDF(algorithm=hashes.SHA256(), length=96, salt=None,
               info=b"chat-v2 keys|" + client_eph + server_eph).derive(shared)
    c2s, s2c, session_id = okm[:32], okm[32:64], okm[64:96]
    if role == "client":
        return Channel(send_key=c2s, recv_key=s2c, session_id=session_id)
    return Channel(send_key=s2c, recv_key=c2s, session_id=session_id)


# ---------- Mots de passe ----------
# On ne stocke JAMAIS un mot de passe en clair : on stocke un "hash"
# (empreinte irréversible) calculé avec un "sel" aléatoire.
# À la connexion, le mot de passe n'est jamais envoyé : le client prouve qu'il
# le connaît en répondant à un défi aléatoire (voir auth_proof).

def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)


def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    return hmac.compare_digest(hash_password(password, salt), expected_hash)


def auth_proof(password_hash: bytes, challenge: bytes, session_id: bytes) -> bytes:
    """Preuve de connaissance du mot de passe (défi/réponse HMAC).

    Le défi est aléatoire (change à chaque tentative) et la preuve est liée à la
    session : elle ne sert à rien si un attaquant la rejoue ailleurs.
    """
    return hmac.new(password_hash, b"auth|" + challenge + session_id, "sha256").digest()


def ask_password(prompt: str) -> str:
    """Saisie masquée dans un vrai terminal (rien ne s'affiche quand on tape)."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return input(prompt)
