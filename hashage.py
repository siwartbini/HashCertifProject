import hashlib
import bcrypt

def main():
    while True:
        print("Menu:")
        print("a- Hacher le mot par sha256")
        print("b- Hacher le mot en générant un salt (bcrypt)")
        print("c- Attaquer par dictionnaire le mot inséré")
        print("d- Revenir au menu principal")

        choice = input("Choisissez une option (a/b/c/d): ")

        if choice == 'a':
            word = input("Entrez le mot à hacher : ")
            sha256_hash = hashlib.sha256(word.encode()).hexdigest()
            print(f"Le hachage SHA-256 du mot est : {sha256_hash}")
        elif choice == 'b':
            word = input("Entrez le mot à hacher : ")
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(word.encode(), salt)
            print(f"Le hachage bcrypt du mot est : {hashed}")
        elif choice == 'c':
            dictionary = ["password", "123456", "qwerty", "letmein", "admin", "love", "monkey", "welcome"]
            def dictionary_attack(target_password):
                for word in dictionary:
                    if word == target_password:
                        return word 
                return None  

            def dictionnaire():
                target_password = input("Entrez le mot de passe cible : ")

                result = dictionary_attack(target_password)

                if result:
                    print(f"Le mot de passe a été trouvé dans le dictionnaire : {result}")
                else:
                    print("Le mot de passe n'a pas été trouvé dans le dictionnaire.")
            x=dictionnaire()
            print(x)
        elif choice == 'd':
            break
        else:
            print("Option invalide. Veuillez choisir une option valide.")

if __name__ == "__main__":
    main()
