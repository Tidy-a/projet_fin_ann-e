"""Client graphique (Tkinter) pour le chat chiffré.

Usage :  python gui_client.py

Compatible avec server.py ET gui_server.py (même protocole que client.py).
L'interface ne contient aucune cryptographie : elle appelle chat_core.py,
qui utilise les fonctions de common.py.
"""
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from cryptography.exceptions import InvalidSignature, InvalidTag

import ui_theme as ui
from chat_core import ClientCore, pretty_fp, remember_server, trust_status
from common import PORT


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Chat chiffré - Client")
        root.geometry("520x600")
        root.minsize(480, 560)
        ui.setup_style(root)

        self.events = queue.Queue()     # le thread réseau poste ici, Tk lit ici
        self.core = None
        self.closing = False
        self.show_cipher = tk.BooleanVar(value=True)
        self.login_frame = None
        self.chat_frame = None

        self.build_login()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(100, self.poll)

    # ------------------------------------------------------------ écran 1 : connexion
    def build_login(self):
        outer = ttk.Frame(self.root)
        outer.pack(fill="both", expand=True)
        self.login_frame = outer

        head = ttk.Frame(outer, style="Header.TFrame", padding=(26, 22))
        head.pack(fill="x")
        ui.lock_icon(head, 46).pack(side="left", padx=(0, 16))
        titles = ttk.Frame(head, style="Header.TFrame")
        titles.pack(side="left")
        ttk.Label(titles, text="Chat chiffré", style="HeaderBig.TLabel").pack(anchor="w")
        ttk.Label(titles, text="Connexion sécurisée au serveur",
                  style="HeaderMuted.TLabel").pack(anchor="w")

        card = ui.card(outer)
        card.pack(padx=30, pady=26, fill="x")
        inner = ttk.Frame(card, style="Card.TFrame", padding=(24, 20))
        inner.pack(fill="x")
        inner.columnconfigure(0, weight=1)

        self.host_var = tk.StringVar(value="127.0.0.1")
        self.port_var = tk.StringVar(value=str(PORT))
        self.user_var = tk.StringVar()
        self.pass_var = tk.StringVar()

        row = 0
        for label, var, show in (("Adresse IP du serveur", self.host_var, ""),
                                 ("Port", self.port_var, ""),
                                 ("Nom d'utilisateur", self.user_var, ""),
                                 ("Mot de passe", self.pass_var, "*")):
            ttk.Label(inner, text=label, style="CardMuted.TLabel").grid(
                row=row, column=0, sticky="w", pady=(8, 2))
            entry = ttk.Entry(inner, textvariable=var, show=show, font=ui.F_BASE)
            entry.grid(row=row + 1, column=0, sticky="ew")
            entry.bind("<Return>", lambda e: self.on_connect())
            if label == "Nom d'utilisateur":
                entry.focus_set()
            row += 2

        self.connect_btn = ttk.Button(inner, text="Se connecter", style="Accent.TButton",
                                      command=self.on_connect)
        self.connect_btn.grid(row=row, column=0, sticky="ew", pady=(18, 6))
        self.status = ttk.Label(inner, text="", style="Error.TLabel", wraplength=380,
                                justify="left")
        self.status.grid(row=row + 1, column=0, sticky="w")

        ttk.Label(outer, text="Échange de clés X25519 signé RSA  ·  messages AES-256-GCM",
                  style="Muted.TLabel", font=ui.F_SMALL).pack(side="bottom", pady=(0, 14))

    def set_status(self, text, error=True):
        self.status.config(text=text, foreground=ui.RED if error else ui.MUTED)

    def on_connect(self):
        if str(self.connect_btn["state"]) == "disabled":
            return
        host = self.host_var.get().strip()
        user = self.user_var.get().strip()
        password = self.pass_var.get()
        try:
            port = int(self.port_var.get())
        except ValueError:
            self.set_status("Le port doit être un nombre.")
            return
        if not host or not user or not password:
            self.set_status("Remplissez tous les champs.")
            return
        self.connect_btn.config(state="disabled")
        self.set_status("Connexion en cours...", error=False)
        threading.Thread(target=self.network_thread,
                         args=(host, port, user, password), daemon=True).start()

    # ------------------------------------------------- thread réseau (pas de Tk ici)
    def network_thread(self, host, port, user, password):
        core = ClientCore()
        # --- phase 1 : connexion, handshake, vérification du serveur, login
        try:
            pem = core.connect(host, port)
            core.handshake(pem)                 # clés éphémères + signature RSA du serveur
            state, fp = trust_status(host, port, pem)
            if state == "changed":
                core.close()
                self.events.put(("fatal",
                    "ALERTE : l'empreinte du serveur a CHANGÉ !\n\n"
                    "Possible attaque de l'homme du milieu (ou le serveur a "
                    "régénéré sa clé). Connexion refusée."))
                return
            if state == "new":
                core.set_timeout(None)
                holder = {"event": threading.Event(), "answer": False}
                self.events.put(("ask_trust", fp, holder))
                holder["event"].wait(240)
                if not holder["answer"]:
                    core.close()
                    self.events.put(("fail", "Connexion annulée."))
                    return
                remember_server(host, port, fp)
            core.set_timeout(15)
            self.events.put(("status", "Canal chiffré établi. Authentification..."))
            reply = core.login(user, password)
            if reply != "OK":
                core.close()
                self.events.put(("fail",
                    "Trop d'échecs : accès refusé." if reply == "LOCKED"
                    else "Identifiants incorrects."))
                return
            core.set_timeout(None)
        except InvalidSignature:
            core.close()
            self.events.put(("fatal",
                "Signature du serveur INVALIDE : le serveur est peut-être usurpé. "
                "Connexion coupée."))
            return
        except ConnectionError:
            core.close()
            self.events.put(("fail",
                "Connexion fermée par le serveur. Si vous avez fait trop d'erreurs "
                "de mot de passe, attendez une minute."))
            return
        except OSError as e:
            core.close()
            self.events.put(("fail",
                f"Impossible de joindre le serveur ({e}).\n"
                "Vérifiez l'adresse IP, le port, le pare-feu et que le serveur est lancé."))
            return
        except (InvalidTag, ValueError) as e:
            core.close()
            self.events.put(("fail", f"Erreur de sécurité pendant la connexion ({e})."))
            return

        self.core = core
        self.events.put(("connected", host, port, user, fp))

        # --- phase 2 : écoute des messages du serveur
        try:
            while True:
                text, data = core.receive()
                self.events.put(("msg", text, data.hex()))
        except (ConnectionError, OSError, InvalidTag, ValueError):
            if not self.closing:
                self.events.put(("closed",
                    "Connexion fermée par le serveur (ou message altéré/rejoué)."))

    # ------------------------------------------------- événements -> interface
    def poll(self):
        try:
            while True:
                self.handle(self.events.get_nowait())
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def handle(self, ev):
        kind = ev[0]
        if kind == "status" and self.login_frame:
            self.set_status(ev[1], error=False)
        elif kind == "ask_trust":
            _, fp, holder = ev
            holder["answer"] = ui.ask_trust(self.root, pretty_fp(fp))
            holder["event"].set()
        elif kind in ("fail", "fatal"):
            if kind == "fatal":
                messagebox.showerror("Alerte de sécurité", ev[1], parent=self.root)
            if self.login_frame:
                self.connect_btn.config(state="normal")
                self.set_status(ev[1].split("\n")[0] if kind == "fatal" else ev[1])
        elif kind == "connected":
            self.build_chat(*ev[1:])
        elif kind == "msg" and self.chat_frame is not None:
            _, text, hexdata = ev
            self.chat.add_message("Serveur", text, mine=False,
                                  cipher_label="chiffré reçu" if self.show_cipher.get() else None,
                                  cipher_hex=hexdata if self.show_cipher.get() else None)
        elif kind == "closed" and self.chat_frame is not None:
            self.chat.add_system(ev[1], "alert")
            self.entry.config(state="disabled")
            self.send_btn.config(state="disabled")

    # ------------------------------------------------------------ écran 2 : discussion
    def build_chat(self, host, port, user, fp):
        self.login_frame.destroy()
        self.login_frame = None
        self.root.geometry("760x680")
        self.root.minsize(560, 480)

        outer = ttk.Frame(self.root)
        outer.pack(fill="both", expand=True)
        self.chat_frame = outer

        head = ttk.Frame(outer, style="Header.TFrame", padding=(18, 12))
        head.pack(fill="x")
        ui.lock_icon(head, 32).pack(side="left", padx=(0, 12))
        info = ttk.Frame(head, style="Header.TFrame")
        info.pack(side="left")
        ttk.Label(info, text=f"{user}  ·  {host}:{port}", style="Header.TLabel").pack(anchor="w")
        ttk.Label(info, text=f"Empreinte du serveur : {fp[:24]}...",
                  style="HeaderMuted.TLabel").pack(anchor="w")
        tk.Label(head, text="  Chiffré AES-256-GCM  ", bg="#14532d", fg="#bbf7d0",
                 font=ui.F_SMALL, padx=6, pady=4).pack(side="right")

        body = ttk.Frame(outer, padding=(14, 12, 14, 12))
        body.pack(fill="both", expand=True)

        bottom = ttk.Frame(body)
        bottom.pack(side="bottom", fill="x")
        ttk.Checkbutton(bottom, text="Afficher les messages chiffrés (démonstration)",
                        variable=self.show_cipher).pack(anchor="w", pady=(8, 8))
        row = ttk.Frame(bottom)
        row.pack(fill="x")
        self.entry = ttk.Entry(row, font=ui.F_BASE)
        self.entry.pack(side="left", fill="x", expand=True, ipady=2)
        self.entry.bind("<Return>", lambda e: self.on_send())
        self.entry.focus_set()
        self.send_btn = ttk.Button(row, text="Envoyer", style="Accent.TButton",
                                   command=self.on_send)
        self.send_btn.pack(side="left", padx=(10, 0))

        self.chat = ui.ChatView(body)
        self.chat.pack(fill="both", expand=True)
        self.chat.add_system("Canal chiffré établi : vos messages sont protégés de bout en bout.", "ok")
        self.chat.add_system("Écrivez 'quit' pour vous déconnecter.", "sys")

    def on_send(self):
        message = self.entry.get().strip()
        if not message or self.core is None:
            return
        self.entry.delete(0, "end")
        try:
            data = self.core.send(message)
        except OSError:
            self.chat.add_system("Envoi impossible : connexion perdue.", "alert")
            return
        show = self.show_cipher.get()
        self.chat.add_message("Vous", message, mine=True,
                              cipher_label="chiffré envoyé" if show else None,
                              cipher_hex=data.hex() if show else None)
        if message.lower() == "quit":
            self.closing = True
            self.core.close()
            self.core = None
            self.chat.add_system("Déconnecté.", "sys")
            self.entry.config(state="disabled")
            self.send_btn.config(state="disabled")

    def on_close(self):
        self.closing = True
        if self.core is not None:
            try:
                self.core.send("quit")
            except OSError:
                pass
            self.core.close()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
