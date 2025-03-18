import base58
from cryptography.hazmat.primitives import serialization, hashes
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Load the RSA private key from file
with open("certs/private_key.pem", "rb") as f:
    rsa_private_key = load_pem_private_key(f.read(), password=None, backend=default_backend())

# Extract RSA private exponent (d) and hash it for deterministic ECC key derivation
rsa_private_bytes = rsa_private_key.private_numbers().d.to_bytes(256, 'big')
seed = hashlib.sha256(rsa_private_bytes).digest()

# Derive an ECC private key from the hashed seed
ecc_private_key = ec.derive_private_key(int.from_bytes(seed, "big") % SECP256K1_ORDER, ec.SECP256K1())

# Get the ECC public key
ecc_public_key = ecc_private_key.public_key()
ecc_public_bytes = ecc_public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

# Encode the ECC public key in Base58 for did:key format
encoded_key = base58.b58encode(ecc_public_bytes).decode()

# Construct the did:key identifier
did_key = f"did:key:z{encoded_key}"
print(f"Deterministic did:key: {did_key}")

# Derive a seed from the RSA private key using SHA-256
rsa_private_bytes = rsa_private_key.private_numbers().d.to_bytes(256, 'big')  # Convert to bytes
seed = hashlib.sha256(rsa_private_bytes).digest()

seed_int = int.from_bytes(seed, "big") % SECP256K1_ORDER
ecc_private_key = ec.derive_private_key(seed_int, ec.SECP256K1())
# Use the seed to generate an ECC private key (Ed25519)
#ecc_private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())

# Get the ECC public key
ecc_public_key = ecc_private_key.public_key()
ecc_public_bytes = ecc_public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

# Encode the ECC public key in Base58 for did:key format
encoded_key = base58.b58encode(ecc_public_bytes).decode()

# Export the private key in PEM format
ecc_private_pem = ecc_private_key.private_bytes(Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())

# Write the ECC private key to a file
with open("certs/Issuer_ecc_private_key.pem", "wb") as f:
    f.write(ecc_private_pem)

# Construct the did:key identifier
did_key = f"did:key:z{encoded_key}"
print(f"Generated did:key: {did_key}")

# Message to sign
message = b"Hello, DID World!"

# Sign the message using the ECC private key
signature = ecc_private_key.sign(message, ec.ECDSA(hashes.SHA256()))

# Convert signature to hex
print(f"Signature: {signature.hex()}")

## Generate a new public private key pair for the holder
# Generate a new ECC private key (Ed25519)
holder_ecc_private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())

# Get the ECC public key
holder_ecc_public_key = holder_ecc_private_key.public_key()
holder_ecc_public_bytes = holder_ecc_public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

# Encode the ECC public key in Base58 for did:key format
holder_encoded_key = base58.b58encode(holder_ecc_public_bytes).decode()

# Construct the did:key identifier
holder_did_key = f"did:key:z{holder_encoded_key}"
print(f"Holder did:key: {holder_did_key}")

# Export the private key in PEM format
holder_ecc_private_pem = holder_ecc_private_key.private_bytes(Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())

# Write the ECC private key to a file
with open("certs/Holder_ecc_private_key.pem", "wb") as f:
    f.write(holder_ecc_private_pem)





