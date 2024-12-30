from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

class Crypto:
    def generate_key_pair():

        # Generate ECDSA private key
        private_key = ec.generate_private_key(ec.SECP256R1())  # You can replace SECP256R1 with other curves like SECP384R1

        # Serialize private key to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # Use a password here if encryption is needed
        )

        # Generate the corresponding public key
        public_key = private_key.public_key()

        # Serialize public key to PEM format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return (public_pem, private_pem)
    
def derive_session_key(peer_public_key, private_key):
    """
    Derives a shared session key using ECDH (Elliptic Curve Diffie-Hellman).

    Args:
        peer_public_key: The public key of the peer (EllipticCurvePublicKey).
        private_key: Your private key (EllipticCurvePrivateKey).

    Returns:
        A derived session key as bytes.
    """
    # Perform key agreement to derive the shared secret
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    # Use HKDF to derive a symmetric session key from the shared secret
    derived_key = HKDF(
        algorithm=SHA256(),
        length=32,  # Length of the derived key in bytes
        salt=None,  # You can provide a salt for better security
        info=b"session_key",  # Contextual information
        backend=default_backend()
    ).derive(shared_secret)

    return derived_key
