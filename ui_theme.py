"""ui_theme.py - Apparence commune des deux interfaces (couleurs, polices, widgets).

Aucune cryptographie ni aucun réseau ici : uniquement de l'affichage.
"""
import sys
import time
import tkinter as tk
from tkinter import ttk

# ---------------------------------------------------------------- palette
BG = "#f1f5f9"          # fond des fenêtres
CARD = "#ffffff"        # cartes blanches
CHAT_BG = "#f8fafc"     # fond de la zone de discussion
NAVY = "#0f172a"        # bandeau du haut
NAVY_2 = "#1e293b"
ACCENT = "#2563eb"      # bleu principal
ACCENT_DARK = "#1d4ed8"
ACCENT_SOFT = "#dbeafe"
GREEN = "#16a34a"
GREEN_SOFT = "#dcfce7"
RED = "#dc2626"
ORANGE = "#ea580c"
TEXT = "#0f172a"
MUTED = "#64748b"
LIGHT = "#94a3b8"
BORDER = "#e2e8f0"
BUBBLE_OTHER = "#e2e8f0"
USER_COLORS = ["#2563eb", "#9333ea", "#db2777", "#0d9488", "#ea580c", "#4f46e5"]

# ---------------------------------------------------------------- polices
if sys.platform.startswith("win"):
    _SANS, _MONO = "Segoe UI", "Consolas"
elif sys.platform == "darwin":
    _SANS, _MONO = "Helvetica Neue", "Menlo"
else:
    _SANS, _MONO = "DejaVu Sans", "DejaVu Sans Mono"

F_BASE = (_SANS, 10)
F_BOLD = (_SANS, 10, "bold")
F_SMALL = (_SANS, 9)
F_TINY = (_SANS, 8)
F_TITLE = (_SANS, 16, "bold")
F_HEAD = (_SANS, 13, "bold")
F_BIG = (_SANS, 15, "bold")
F_MONO = (_MONO, 10)
F_MONO_S = (_MONO, 8)


def setup_style(root):
    """Applique le thème à toute la fenêtre."""
    style = ttk.Style(root)
    try:
        style.theme_use("clam")          # thème qui accepte les couleurs personnalisées
    except tk.TclError:
        pass
    root.configure(bg=BG)

    style.configure(".", font=F_BASE, background=BG, foreground=TEXT)
    style.configure("TFrame", background=BG)
    style.configure("Card.TFrame", background=CARD)
    style.configure("Header.TFrame", background=NAVY)
    style.configure("Header2.TFrame", background=NAVY_2)

    style.configure("TLabel", background=BG, foreground=TEXT, font=F_BASE)
    style.configure("Card.TLabel", background=CARD)
    style.configure("Muted.TLabel", background=BG, foreground=MUTED)
    style.configure("CardMuted.TLabel", background=CARD, foreground=MUTED, font=F_SMALL)
    style.configure("CardBold.TLabel", background=CARD, font=F_BOLD)
    style.configure("Error.TLabel", background=CARD, foreground=RED, font=F_SMALL)
    style.configure("Header.TLabel", background=NAVY, foreground="white", font=F_HEAD)
    style.configure("HeaderBig.TLabel", background=NAVY, foreground="white", font=F_BIG)
    style.configure("HeaderMuted.TLabel", background=NAVY, foreground=LIGHT, font=F_SMALL)
    style.configure("Header2.TLabel", background=NAVY_2, foreground=LIGHT, font=F_SMALL)
    style.configure("HeaderMono.TLabel", background=NAVY_2, foreground="#e2e8f0", font=F_MONO)

    style.configure("Accent.TButton", background=ACCENT, foreground="white", borderwidth=0,
                    focusthickness=0, padding=(18, 9), font=F_BOLD)
    style.map("Accent.TButton",
              background=[("disabled", "#93c5fd"), ("pressed", ACCENT_DARK), ("active", ACCENT_DARK)],
              foreground=[("disabled", "white")])
    style.configure("Soft.TButton", background=ACCENT_SOFT, foreground=ACCENT_DARK, borderwidth=0,
                    focusthickness=0, padding=(14, 8), font=F_BOLD)
    style.map("Soft.TButton",
              background=[("pressed", "#bfdbfe"), ("active", "#bfdbfe")])
    style.configure("Ghost.TButton", background=NAVY_2, foreground="#e2e8f0", borderwidth=0,
                    focusthickness=0, padding=(10, 4), font=F_SMALL)
    style.map("Ghost.TButton", background=[("active", "#334155"), ("pressed", "#334155")])

    style.configure("TEntry", fieldbackground="white", foreground=TEXT, padding=8,
                    bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER, insertcolor=TEXT)
    style.map("TEntry", bordercolor=[("focus", ACCENT)], lightcolor=[("focus", ACCENT)],
              darkcolor=[("focus", ACCENT)])
    style.configure("TCheckbutton", background=BG, foreground=MUTED, font=F_SMALL)
    style.map("TCheckbutton", background=[("active", BG)])
    style.configure("Vertical.TScrollbar", background=BORDER, troughcolor=CHAT_BG,
                    bordercolor=CHAT_BG, arrowcolor=MUTED, relief="flat")


def card(parent, **kw):
    """Cadre blanc avec une fine bordure."""
    return tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1, **kw)


def lock_icon(parent, size=36, bg=NAVY, color="white"):
    """Petit cadenas dessiné (pas besoin d'image)."""
    c = tk.Canvas(parent, width=size, height=size, bg=bg, highlightthickness=0, bd=0)
    w = size
    lw = max(2, size // 9)
    c.create_arc(w * 0.28, w * 0.08, w * 0.72, w * 0.56, start=0, extent=180,
                 style="arc", width=lw, outline=color)
    c.create_line(w * 0.28, w * 0.32, w * 0.28, w * 0.48, width=lw, fill=color)
    c.create_line(w * 0.72, w * 0.32, w * 0.72, w * 0.48, width=lw, fill=color)
    c.create_rectangle(w * 0.18, w * 0.44, w * 0.82, w * 0.90, fill=color, outline=color)
    c.create_oval(w * 0.44, w * 0.56, w * 0.56, w * 0.68, fill=bg, outline=bg)
    c.create_rectangle(w * 0.475, w * 0.63, w * 0.525, w * 0.78, fill=bg, outline=bg)
    return c


def pill(parent, text, bg=GREEN_SOFT, fg=GREEN):
    return tk.Label(parent, text=text, bg=bg, fg=fg, font=F_SMALL, padx=10, pady=3)


# ---------------------------------------------------------------- zone de discussion

class ChatView(tk.Frame):
    """Zone de messages en 'bulles' (les miens à droite en bleu, les autres à gauche)."""

    def __init__(self, parent):
        super().__init__(parent, bg=CHAT_BG, highlightbackground=BORDER, highlightthickness=1)
        self.text = tk.Text(self, wrap="word", state="disabled", bd=0, highlightthickness=0,
                            bg=CHAT_BG, fg=TEXT, padx=14, pady=12, cursor="arrow",
                            font=F_BASE, insertwidth=0, takefocus=0)
        bar = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)
        self._user_tags = {}

        t = self.text
        t.tag_configure("meta_me", font=F_TINY, foreground=MUTED, justify="right", rmargin=8,
                        spacing1=4)
        t.tag_configure("me", background=ACCENT, foreground="white", font=F_BASE,
                        justify="right", lmargin1=110, lmargin2=110, rmargin=8)
        t.tag_configure("line_me", justify="right", lmargin1=110, lmargin2=110, rmargin=8)
        t.tag_configure("other", background=BUBBLE_OTHER, foreground=TEXT, font=F_BASE,
                        justify="left", lmargin1=8, lmargin2=8, rmargin=110)
        t.tag_configure("line_other", justify="left", lmargin1=8, lmargin2=8, rmargin=110)
        t.tag_configure("cipher_l", font=F_MONO_S, foreground=LIGHT, lmargin1=8, lmargin2=8,
                        spacing1=2)
        t.tag_configure("cipher_r", font=F_MONO_S, foreground=LIGHT, justify="right", rmargin=8,
                        spacing1=2)
        t.tag_configure("gap", font=(_SANS, 5))
        t.tag_configure("sys", font=F_SMALL, foreground=MUTED, justify="center",
                        spacing1=6, spacing3=6)
        t.tag_configure("ok", font=F_SMALL, foreground=GREEN, justify="center",
                        spacing1=6, spacing3=6)
        t.tag_configure("warn", font=F_SMALL, foreground=ORANGE, justify="center",
                        spacing1=6, spacing3=6)
        t.tag_configure("alert", font=F_BOLD, foreground=RED, justify="center",
                        spacing1=8, spacing3=8)

    # -- outils internes
    def _user_tag(self, name):
        tag = self._user_tags.get(name)
        if tag is None:
            color = USER_COLORS[sum(map(ord, name)) % len(USER_COLORS)]
            tag = f"meta_u{len(self._user_tags)}"
            self.text.tag_configure(tag, font=(_SANS, 8, "bold"), foreground=color,
                                    lmargin1=8, lmargin2=8, spacing1=4)
            self._user_tags[name] = tag
        return tag

    def _insert(self, content, tags):
        self.text.configure(state="normal")
        self.text.insert("end", content, tags)
        self.text.configure(state="disabled")

    def _scroll(self):
        self.text.see("end")

    # -- API publique
    def add_message(self, who, content, mine, cipher_label=None, cipher_hex=None):
        """Une bulle de message, avec (option) le texte chiffré en dessous."""
        stamp = time.strftime("%H:%M")
        self._insert(f"{who}   {stamp}\n", ("meta_me" if mine else self._user_tag(who),))
        self._insert(f" {content} ", ("me" if mine else "other",))
        self._insert("\n", ("line_me" if mine else "line_other",))
        if cipher_hex:
            self.add_cipher(cipher_label or "chiffré", cipher_hex, right=mine)
        self._insert("\n", ("gap",))
        self._scroll()

    def add_cipher(self, label, hex_text, right=False):
        self._insert(f"{label} : {hex_text[:40]}...\n", ("cipher_r" if right else "cipher_l",))
        self._scroll()

    def add_system(self, content, kind="sys"):
        self._insert(content + "\n", (kind,))
        self._scroll()


# ---------------------------------------------------------------- boîtes de dialogue

def _show_modal(win, parent):
    win.transient(parent)
    win.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() - win.winfo_width()) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - win.winfo_height()) // 3
    win.geometry(f"+{max(x, 0)}+{max(y, 0)}")
    try:
        win.wait_visibility()
        win.grab_set()
    except tk.TclError:
        pass
    parent.wait_window(win)


def ask_trust(parent, fp_pretty):
    """Fenêtre 'première connexion' : affiche l'empreinte, retourne True si l'utilisateur fait confiance."""
    win = tk.Toplevel(parent)
    win.title("Première connexion")
    win.configure(bg=CARD)
    win.resizable(False, False)
    result = {"ok": False}

    body = ttk.Frame(win, style="Card.TFrame", padding=22)
    body.pack()
    ttk.Label(body, text="Faire confiance à ce serveur ?", style="Card.TLabel",
              font=F_HEAD).pack(anchor="w")
    ttk.Label(body, style="CardMuted.TLabel", justify="left", wraplength=420,
              text="C'est la première fois que vous vous connectez à ce serveur. "
                   "Comparez l'empreinte ci-dessous avec celle affichée dans la "
                   "fenêtre du serveur : elles doivent être identiques.").pack(anchor="w", pady=(6, 12))
    box = tk.Frame(body, bg=NAVY, padx=14, pady=10)
    box.pack(fill="x")
    tk.Label(box, text=fp_pretty, bg=NAVY, fg="#e2e8f0", font=F_MONO, justify="left").pack()
    ttk.Label(body, style="CardMuted.TLabel", justify="left", wraplength=420,
              text="Si elles sont différentes, annulez : quelqu'un se fait peut-être "
                   "passer pour le serveur.").pack(anchor="w", pady=(10, 14))

    def yes():
        result["ok"] = True
        win.destroy()

    row = ttk.Frame(body, style="Card.TFrame")
    row.pack(fill="x")
    ttk.Button(row, text="Faire confiance", style="Accent.TButton", command=yes).pack(side="right")
    ttk.Button(row, text="Annuler", style="Soft.TButton", command=win.destroy).pack(side="right", padx=8)
    win.protocol("WM_DELETE_WINDOW", win.destroy)
    _show_modal(win, parent)
    return result["ok"]


def ask_new_user(parent):
    """Fenêtre 'ajouter un utilisateur'. Retourne (nom, mot de passe) ou None."""
    win = tk.Toplevel(parent)
    win.title("Ajouter un utilisateur")
    win.configure(bg=CARD)
    win.resizable(False, False)
    result = {}

    body = ttk.Frame(win, style="Card.TFrame", padding=22)
    body.pack()
    ttk.Label(body, text="Nouvel utilisateur", style="Card.TLabel", font=F_HEAD).pack(anchor="w", pady=(0, 10))

    name_var, pw_var, pw2_var = tk.StringVar(), tk.StringVar(), tk.StringVar()
    entries = []
    for label, var, show in (("Nom d'utilisateur", name_var, ""),
                             ("Mot de passe", pw_var, "*"),
                             ("Confirmer le mot de passe", pw2_var, "*")):
        ttk.Label(body, text=label, style="CardMuted.TLabel").pack(anchor="w", pady=(6, 2))
        e = ttk.Entry(body, textvariable=var, width=34, show=show, font=F_BASE)
        e.pack(fill="x")
        entries.append(e)
    error = ttk.Label(body, text="", style="Error.TLabel", wraplength=300)
    error.pack(anchor="w", pady=(8, 0))

    def ok(_event=None):
        name = name_var.get().strip()
        if not name:
            error.config(text="Entrez un nom d'utilisateur.")
        elif not pw_var.get():
            error.config(text="Entrez un mot de passe.")
        elif pw_var.get() != pw2_var.get():
            error.config(text="Les deux mots de passe sont différents.")
        else:
            result["value"] = (name, pw_var.get())
            win.destroy()

    row = ttk.Frame(body, style="Card.TFrame")
    row.pack(fill="x", pady=(12, 0))
    ttk.Button(row, text="Créer", style="Accent.TButton", command=ok).pack(side="right")
    ttk.Button(row, text="Annuler", style="Soft.TButton", command=win.destroy).pack(side="right", padx=8)
    for e in entries:
        e.bind("<Return>", ok)
    entries[0].focus_set()
    win.protocol("WM_DELETE_WINDOW", win.destroy)
    _show_modal(win, parent)
    return result.get("value")
