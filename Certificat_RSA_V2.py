from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import datetime


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

def generate_self_signed_certificate():
    private_key = None

    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    certificate = x509.CertificateBuilder().subject_name(subject)
    certificate = certificate.issuer_name(issuer)
    certificate = certificate.public_key(private_key.public_key())
    certificate = certificate.serial_number(x509.random_serial_number())
    certificate = certificate.not_valid_before(datetime.datetime.utcnow())
    certificate = certificate.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    certificate = certificate.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    certificate = certificate.sign(private_key, hashes.SHA256(), default_backend())

    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
    with open('self_signed_certificate.pem', 'wb') as f:
        f.write(certificate_pem)

    print("Certificat autosigné généré et sauvegardé dans self_signed_certificate.pem")


def Certificat_RSA():
    while True:
        print("Menu:")
        print("a- Générer une paire de clés RSA")
        print("b- Générer un certificat autosigné par RSA")
        print("c- Chiffrer un message par ce certificat")
        print("d- Revenir au menu principal")

        choice = input("Choisissez une option (a/b/c/d): ")

        if choice == 'a':
            generate_key_pair()
        elif choice == 'b':
            generate_self_signed_certificate()
        elif choice == 'c':
            print("Chiffrement de message avec un certificat nécessite généralement l'utilisation de la clé publique associée au certificat.")
        elif choice == 'd':
            break
        else:
            print("Option invalide. Veuillez choisir une option valide.")

if __name__ == "__main__":
    Certificat_RSA()
