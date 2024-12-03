import secp256k1
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from datetime import datetime, timedelta

# Step 1: Use a 32-byte hex private key
hex_private_key = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"

# Convert the hex string to bytes
private_key_bytes = bytes.fromhex(hex_private_key)

# Step 2: Initialize secp256k1 PrivateKey
ctx = secp256k1.PrivateKey(private_key_bytes)

# Generate public key
public_key = ctx.pubkey
public_key_serialized = public_key.serialize(compressed=False)

# Print public key for verification
print("Public Key (uncompressed):", public_key_serialized.hex())

# Step 3: Wrap the secp256k1 private key for use with X.509
private_key_ec = ec.derive_private_key(int(hex_private_key, 16), ec.SECP256K1())

# Save the private key to PEM format
private_key_pem = private_key_ec.private_bytes(
    encoding=Encoding.PEM,
    format=PrivateFormat.PKCS8,
    encryption_algorithm=NoEncryption()
)
with open("private_key.pem", "wb") as f:
    f.write(private_key_pem)

# Save the public key to PEM format
public_key_pem = private_key_ec.public_key().public_bytes(
    encoding=Encoding.PEM,
    format=PublicFormat.SubjectPublicKeyInfo
)
with open("public_key.pem", "wb") as f:
    f.write(public_key_pem)

# Step 4: Create an X.509 Certificate Signing Request (CSR)
csr = x509.CertificateSigningRequestBuilder().subject_name(
    x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"example.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Example Org"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    ])
).sign(private_key_ec, hashes.SHA256())

# Save the CSR to a file
with open("certificate.csr", "wb") as f:
    f.write(csr.public_bytes(Encoding.PEM))

print("CSR saved as certificate.csr")

# Step 5: Self-sign an X.509 Certificate (Optional)
one_year = timedelta(days=365)
certificate = (
    x509.CertificateBuilder()
    .subject_name(csr.subject)
    .issuer_name(csr.subject)  # Self-signed, so subject = issuer
    .public_key(private_key_ec.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + one_year)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(private_key_ec, hashes.SHA256())
)

# Save the self-signed certificate to a file
with open("self_signed_certificate.pem", "wb") as f:
    f.write(certificate.public_bytes(Encoding.PEM))

print("Self-signed certificate saved as self_signed_certificate.pem")

