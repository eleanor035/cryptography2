from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

# Parameters for the DH group (these should be pre-defined or exchanged securely)
def generate_dh_parameters():
    """Generate DH parameters (group and generator)."""
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    return parameters

# Generate private and public keys
def generate_dh_keys(parameters):
    """Generate DH private and public keys."""
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

# Perform DH key exchange
def perform_dh_key_exchange(private_key, peer_public_key):
    """Perform DH key exchange to derive a shared secret."""
    shared_secret = private_key.exchange(peer_public_key)
    
    # Derive a symmetric key from the shared secret using PBKDF2
    salt = os.urandom(16)  # A random salt for key derivation
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), salt=salt, length=32, iterations=100000)
    derived_key = kdf.derive(shared_secret)
    
    return derived_key, salt  # The derived key can now be used for AES encryption/decryption

