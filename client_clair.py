"""Client SANS chiffrement (démonstration Wireshark uniquement).
Usage : python client_clair.py                 -> serveur sur cette machine
        python client_clair.py 192.168.1.20    -> serveur sur une autre machine
"""
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = 5001

c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.connect((HOST, PORT))
print(f"[*] Connecté à {HOST}:{PORT} (SANS chiffrement)")

user = input("Utilisateur : ")
password = input("Mot de passe : ")
c.send(f"{user}:{password}".encode())
if c.recv(1024).decode().strip() != "OK":
    print("[!] Accès refusé")
    c.close()
    raise SystemExit

print("[*] Authentification réussie. Tapez 'quit' pour quitter.\n")
while True:
    message = input("Vous > ")
    if not message:
        continue
    c.send(message.encode())
    if message.lower() == "quit":
        break
    print("Réponse >", c.recv(1024).decode().strip())
c.close()
