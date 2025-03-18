### Create a presentation of a proof from the holder with the credential and holders private key

import json
import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

# Load the holder's private key from the PEM file
with open("certs/Holder_ecc_private_key.pem", "rb") as f:
    holder_ecc_private_key = load_pem_private_key(f.read(), password=None)

# Get the holder's public key
holder_public_key = holder_ecc_private_key.public_key()
holder_public_bytes = holder_public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
holder_encoded_key = base58.b58encode(holder_public_bytes).decode()
holder_did_key = f"did:key:z{holder_encoded_key}"
print(f"Holder did:key: {holder_did_key}")

# Get the Issuers private key from the PEM file
with open("certs/Issuer_ecc_private_key.pem", "rb") as f:
    issuer_ecc_private_key = load_pem_private_key(f.read(), password=None)

# Get the Issuers public key
issuer_public_key = issuer_ecc_private_key.public_key()
issuer_public_bytes = issuer_public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
issuer_encoded_key = base58.b58encode(issuer_public_bytes).decode()
issuer_did_key = f"did:key:z{issuer_encoded_key}"
print(f"Issuer did:key: {issuer_did_key}")

### Create the presentation with signed_credential.json and the holder's private key
# Load the credential from the file
with open("certs/signed_credential.json", "r") as f:
    credential = json.load(f)

# Create the presentation with the credential and the holder's public key
presentation = {
    "verifiableCredential": [credential],
    "holder": holder_did_key
}

# Serialize the presentation to JSON
presentation_json = json.dumps(presentation, indent=2)
print(presentation_json)

# Export the presentation to a file
with open("certs/presentation.json", "w") as f:
    f.write(presentation_json)

# verify the presentation proof
# Load the presentation from the file
with open("certs/presentation.json", "r") as f:
    presentation = json.load(f) 
    
# Get the holder's public key from the presentation
holder_did_key = presentation["holder"]
holder_encoded_key = holder_did_key[9:]
print(holder_encoded_key)
holder_public_bytes = base58.b58decode(holder_encoded_key)
holder_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), holder_public_bytes)

# Get the credential from the presentation
credential = presentation["verifiableCredential"][0]

# Get the signature value from the credential
signature_b58 = credential["proof"]["signatureValue"]
signature = base58.b58decode(signature_b58)

# Verify the signature
holder_public_key.verify(
    signature,
    presentation_json.encode(),
    ec.ECDSA(hashes.SHA256())
)



