from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open('private_key.pem', 'wb') as f:
        f.write(private_key_pem)

    public_key = private_key.public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('public_key.pem', 'wb') as f:
        f.write(public_key_pem)

    print("Paires de clés RSA générées et sauvegardées dans private_key.pem et public_key.pem")

def encrypt_message():
    with open('public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    message = input("Entrez le message que vous souhaitez chiffrer : ").encode('utf-8')

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open('encrypted_message.bin', 'wb') as f:
        f.write(ciphertext)

    print("Message chiffré et sauvegardé dans encrypted_message.bin")

def decrypt_message():
    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    with open('encrypted_message.bin', 'rb') as f:
        ciphertext = f.read()

    decrypted_message = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("Message déchiffré :")
    print(decrypted_message.decode('utf-8'))

def sign_message():
    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    message = input("Entrez le message que vous souhaitez signer : ").encode('utf-8')

    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    with open('message_signature.bin', 'wb') as f:
        f.write(signature)

    print("Signature générée et sauvegardée dans message_signature.bin")

def verify_signature():
    with open('public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    with open('message_signature.bin', 'rb') as f:
        signature = f.read()

    message = input("Entrez le message pour vérification : ").encode('utf-8')

    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("La signature est valide.")
    except utils.InvalidSignature:
        print("La signature n'est pas valide.")

def chiffrement_rsa():
    while True:
        print("Menu:")
        print("a- Générer les paires de clés RSA")
        print("b- Chiffrer un message par RSA")
        print("c- Déchiffrer un message")
        print("d- Signer un message par RSA")
        print("e- Vérifier la signature du message")
        print("f- Revenir au menu principal")

        choice = input("Choisissez une option (a/b/c/d/e/f): ")

        if choice == 'a':
            generate_key_pair()
        elif choice == 'b':
            encrypt_message()
        elif choice == 'c':
            decrypt_message()
        elif choice == 'd':
            sign_message()
        elif choice == 'e':
            verify_signature()
        elif choice == 'f':
            break
        else:
            print("Option invalide. Veuillez choisir une option valide.")

if __name__ == "__main__":
    chiffrement_rsa()
