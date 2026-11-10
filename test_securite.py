"""Tests automatiques des protections de sécurité.   Lancer :  python -m unittest -v test_securite
(aucune interface graphique nécessaire)"""
import os
import socket
import struct
import threading
import time
import unittest

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import common
from common import (Channel, auth_proof, derive_channel, exchange, new_ephemeral,
                    recv_msg, send_msg, sign_handshake, verify_handshake)


def make_channels():
    """Fait un vrai handshake entre un 'client' et un 'serveur' (en mémoire)."""
    c_priv, c_eph = new_ephemeral()
    s_priv, s_eph = new_ephemeral()
    client = derive_channel(exchange(c_priv, s_eph), c_eph, s_eph, "client")
    server = derive_channel(exchange(s_priv, c_eph), c_eph, s_eph, "server")
    return client, server


def pair():
    a, b = socket.socketpair()
    return a, b


class TestHandshake(unittest.TestCase):
    def setUp(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def test_signature_valide(self):
        _, c = new_ephemeral(); _, s = new_ephemeral()
        verify_handshake(self.pem, c, s, sign_handshake(self.key, c, s))

    def test_faux_serveur_signature_refusee(self):
        autre = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _, c = new_ephemeral(); _, s = new_ephemeral()
        with self.assertRaises(InvalidSignature):
            verify_handshake(self.pem, c, s, sign_handshake(autre, c, s))

    def test_signature_liee_aux_cles_ephemeres(self):
        _, c = new_ephemeral(); _, s = new_ephemeral(); _, s2 = new_ephemeral()
        sig = sign_handshake(self.key, c, s)
        with self.assertRaises(InvalidSignature):   # un attaquant remplace sa clé éphémère
            verify_handshake(self.pem, c, s2, sig)

    def test_memes_cles_des_deux_cotes_et_forward_secrecy(self):
        client, server = make_channels()
        self.assertEqual(client.session_id, server.session_id)
        client2, _ = make_channels()                 # 2e session : clés totalement différentes
        self.assertNotEqual(client.session_id, client2.session_id)


class TestCanal(unittest.TestCase):
    def test_aller_retour_dans_les_deux_sens(self):
        client, server = make_channels(); a, b = pair()
        client.send(a, "bonjour é à"); self.assertEqual(server.recv(b)[0], "bonjour é à")
        server.send(b, "salut");       self.assertEqual(client.recv(a)[0], "salut")

    def test_reflexion_refusee(self):
        """Un message du client renvoyé au client (comme s'il venait du serveur) est rejeté."""
        client, _ = make_channels(); a, b = pair()
        client.send(a, "virement 10 euros")
        raw = recv_msg(b)
        send_msg(b, raw)                              # l'attaquant le renvoie au client
        with self.assertRaises(InvalidTag):
            client.recv(a)

    def test_rejeu_refuse(self):
        client, server = make_channels(); a, b = pair()
        client.send(a, "ordre unique")
        raw = recv_msg(b)
        a2, b2 = pair(); send_msg(a2, raw); send_msg(a2, raw)   # même message deux fois
        self.assertEqual(server.recv(b2)[0], "ordre unique")
        with self.assertRaises(InvalidTag):
            server.recv(b2)

    def test_message_supprime_detecte(self):
        client, server = make_channels(); a, b = pair()
        client.send(a, "premier"); client.send(a, "second")
        recv_msg(b)                                   # l'attaquant supprime le 1er message
        a2, b2 = pair(); send_msg(a2, recv_msg(b))
        with self.assertRaises(InvalidTag):
            server.recv(b2)

    def test_modification_detectee(self):
        client, server = make_channels(); a, b = pair()
        client.send(a, "10 euros")
        raw = bytearray(recv_msg(b)); raw[-1] ^= 1
        a2, b2 = pair(); send_msg(a2, bytes(raw))
        with self.assertRaises(InvalidTag):
            server.recv(b2)

    def test_envois_simultanes_gardent_l_ordre(self):
        client, server = make_channels(); a, b = pair()
        threads = [threading.Thread(target=lambda i=i: [client.send(a, f"{i}-{j}") for j in range(20)])
                   for i in range(5)]
        [t.start() for t in threads]
        received = [server.recv(b)[0] for _ in range(100)]   # aucune InvalidTag
        [t.join() for t in threads]
        self.assertEqual(len(received), 100)


class TestLimites(unittest.TestCase):
    def test_message_trop_grand_refuse(self):
        a, b = pair()
        a.sendall(struct.pack(">I", 4_000_000_000))   # annonce 4 Go
        with self.assertRaises(ConnectionError):
            recv_msg(b)

    def test_envoi_trop_grand_refuse(self):
        a, _ = pair()
        with self.assertRaises(ValueError):
            send_msg(a, b"x" * (common.MAX_MSG + 1))


class TestAuthentification(unittest.TestCase):
    def test_preuve_correcte_et_liee_au_defi_et_a_la_session(self):
        key = common.hash_password("secret", b"s" * 16)
        p = auth_proof(key, b"d" * 16, b"S" * 32)
        self.assertEqual(p, auth_proof(key, b"d" * 16, b"S" * 32))
        self.assertNotEqual(p, auth_proof(key, b"e" * 16, b"S" * 32))   # autre défi
        self.assertNotEqual(p, auth_proof(key, b"d" * 16, b"T" * 32))   # autre session
        bad = common.hash_password("faux", b"s" * 16)
        self.assertNotEqual(p, auth_proof(bad, b"d" * 16, b"S" * 32))   # mauvais mot de passe


class TestServeur(unittest.TestCase):
    """Teste server.py en conditions réelles (dans un dossier temporaire)."""

    @classmethod
    def setUpClass(cls):
        import json, tempfile
        cls.old = os.getcwd(); cls.tmp = tempfile.mkdtemp(); os.chdir(cls.tmp)
        salt = os.urandom(16)
        json.dump({"alice": {"salt": salt.hex(),
                             "hash": common.hash_password("pw123", salt).hex()}},
                  open("users.json", "w"))
        import server
        cls.server = server
        server.say = lambda t: None
        server.FAIL_DELAY = 0.05
        cls.srv = socket.socket(); cls.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.srv.bind(("127.0.0.1", 0)); cls.srv.listen()
        cls.port = cls.srv.getsockname()[1]
        threading.Thread(target=server.accept_loop, args=(cls.srv,), daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.old)

    def connect(self):
        from chat_core import ClientCore
        c = ClientCore(); pem = c.connect("127.0.0.1", self.port); c.handshake(pem)
        return c

    def test_bon_mot_de_passe(self):
        self.assertEqual(self.connect().login("alice", "pw123"), "OK")

    def test_mauvais_mot_de_passe(self):
        self.assertEqual(self.connect().login("alice", "faux"), "DENIED")

    def test_utilisateur_inconnu_meme_reponse_et_meme_sel_stable(self):
        c = self.connect()
        self.assertEqual(c.login("inconnu", "x"), "DENIED")
        s1 = self.server.user_record("inconnu")[0]
        s2 = self.server.user_record("inconnu")[0]
        self.assertEqual(s1, s2)                        # faux sel stable
        self.assertEqual(len(s1), 16)                   # même forme qu'un vrai sel

    def test_blocage_apres_trop_d_echecs(self):
        s = self.server
        s.failures.clear()
        for _ in range(s.FAIL_LIMIT):
            s.register_failure("10.9.9.9")
        self.assertTrue(s.is_blocked("10.9.9.9"))
        self.assertFalse(s.is_blocked("10.1.1.1"))
        s.failures["10.9.9.9"] = [time.time() - s.FAIL_WINDOW - 1] * s.FAIL_LIMIT
        self.assertFalse(s.is_blocked("10.9.9.9"))      # le blocage expire

    def test_message_serveur_vers_client(self):
        c = self.connect(); self.assertEqual(c.login("alice", "pw123"), "OK")
        c.set_timeout(5); c.send("coucou"); time.sleep(0.3)
        self.server.broadcast("réponse")
        self.assertEqual(c.receive()[0], "réponse")

    def test_envoi_a_un_seul_client(self):
        """broadcast(only=...) : seul le client visé reçoit le message."""
        c1 = self.connect(); self.assertEqual(c1.login("alice", "pw123"), "OK")
        c2 = self.connect(); self.assertEqual(c2.login("alice", "pw123"), "OK")
        time.sleep(0.4)
        c1.send("je suis le client 1")
        time.sleep(0.4)
        with self.server.clients_lock:
            addrs = list(self.server.clients)
        self.assertGreaterEqual(len(addrs), 2)
        # on cible le client c1 : son adresse locale = clé dans server.clients
        target = c1.sock.getsockname()
        self.assertIn(target, addrs)
        self.server.broadcast("secret pour le client 1", only={target})
        c1.set_timeout(3); c2.set_timeout(0.7)
        self.assertEqual(c1.receive()[0], "secret pour le client 1")
        with self.assertRaises(socket.timeout):       # le client 2 ne reçoit rien
            c2.receive()
        self.assertEqual(self.server.addrs_of_user("ALICE"), set(addrs) & self.server.addrs_of_user("alice"))


if __name__ == "__main__":
    unittest.main()
