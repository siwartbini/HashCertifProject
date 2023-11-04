import re
import getpass
import hashlib
import hashlib
import bcrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from hashage import main
from chiffrement_RSA import chiffrement_rsa
from cryptography.exceptions import InvalidSignature
from Certificat_RSA_V2 import Certificat_RSA


def validatePassword(mot_de_passe):
    if len(mot_de_passe) < 8:
        return False
    if not re.search(r'[A-Z]', mot_de_passe):
        return False
    if not re.search(r'[a-z]', mot_de_passe):
        return False
    if not re.search(r'\d', mot_de_passe):
        return False
    if not re.search(r'[!@#$%^&*]', mot_de_passe):
        return False
    return True

def validateEmail(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

while True:
    email = input("Entrez votre adresse e-mail : ")
    if not validateEmail(email):
        print("Adresse e-mail invalide. Veuillez réessayer.")
    else:
        break

while True:
    mot_de_passe = getpass.getpass("Entrez un mot de passe : ")
    if not validatePassword(mot_de_passe):
        print("Le mot de passe ne respecte pas les critères. Veuillez réessayer.")
    else:
        break

with open("informations.txt", "a") as fichier:
    fichier.write(f"{email}:{mot_de_passe}\n")

print("Informations enregistrées avec succès dans informations.txt.")

def readUserInfo():
    informations_utilisateurs = {}
    with open("informations.txt", "r") as fichier:
        lignes = fichier.readlines()
        for ligne in lignes:
            email, mot_de_passe = ligne.strip().split(":")
            informations_utilisateurs[email] = mot_de_passe
    return informations_utilisateurs


def authentification():
    email = input("Adresse e-mail : ")
    mot_de_passe = getpass.getpass("Mot de passe : ")

    informations_utilisateurs = readUserInfo()

    if email in informations_utilisateurs:
        mot_de_passe_stocke = informations_utilisateurs[email]
        if mot_de_passe == mot_de_passe_stocke:
            print("Authentification réussie. Vous êtes connecté.")
        else:
            print("Mot de passe incorrect.")
    else:
        print("Adresse e-mail non trouvée.")
        

def menu_principal():
    while True:
        print("\nMenu principal :")
        print("1. Fonction de hachage")
        print("2. Chiffrement RSA")
        print("3. Création de certificat RSA")
        print("4. Quitter")

        choix = input("Faites votre choix : ")
       
        if choix == "1":
            main()
        elif choix == "2":
            chiffrement_rsa()
        elif choix == "3":
            Certificat_RSA()
        elif choix == "4":
            print("Au revoir !")
            break
        else:
            print("Choix invalide. Veuillez sélectionner une option valide.")

if __name__ == "__main__":
    while not authentification():
        menu_principal()