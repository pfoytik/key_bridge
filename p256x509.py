from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID
from cryptography import x509
import binascii
from datetime import datetime, timedelta

# Your 32-byte random hex value
hex_private_key = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"  # Replace with your own 32-byte hex key

# Convert the hex value to bytes
private_key_bytes = binascii.unhexlify(hex_private_key)

# Create a private key object using the P-256 curve
private_key = ec.derive_private_key(int.from_bytes(private_key_bytes, "big"), ec.SECP256R1())

# Generate a self-signed certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Corp"),
    x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
])

# Certificate validity
valid_from = datetime.utcnow()
valid_until = valid_from + timedelta(days=365)

# Build the certificate
certificate = x509.CertificateBuilder() \
    .subject_name(subject) \
    .issuer_name(issuer) \
    .public_key(private_key.public_key()) \
    .serial_number(x509.random_serial_number()) \
    .not_valid_before(valid_from) \
    .not_valid_after(valid_until) \
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ) \
    .sign(private_key, hashes.SHA256())

# Save the private key to a PEM file
with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.TraditionalOpenSSL,
        NoEncryption()
    ))

# Save the certificate to a PEM file
with open("certificate.pem", "wb") as f:
    f.write(certificate.public_bytes(Encoding.PEM))

print("Private key and certificate generated!")

