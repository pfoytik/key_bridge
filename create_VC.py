import json
import base58
import hashlib
from ecdsa import SigningKey, SECP256k1, BadSignatureError
from ecdsa.util import sigencode_der
import binascii
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat

### Read the ECC Pem file for Holder and Issuer
with open("certs/Holder_ecc_private_key.pem", "rb") as f:
    holder_ecc_private_key = load_pem_private_key(f.read(), password=None)

with open("certs/Issuer_ecc_private_key.pem", "rb") as f:
    issuer_ecc_private_key = load_pem_private_key(f.read(), password=None)

### create a verified credential for network use issued by the issuer key to the holder key
# Create the credential subject with the holder's public key did
holder_public_key = holder_ecc_private_key.public_key()
holder_public_bytes = holder_public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
holder_encoded_key = base58.b58encode(holder_public_bytes).decode()
holder_did_key = f"did:key:z{holder_encoded_key}"
credential_subject = {
    "id": holder_did_key
}

# Create the credential with the issuer's public key did
issuer_private_key_numbers = issuer_ecc_private_key.private_numbers()
issuer_private_key_bytes = issuer_private_key_numbers.private_value.to_bytes(32, byteorder="big")
issuer_sk = SigningKey.from_string(issuer_private_key_bytes, curve=SECP256k1)
issuer_public_key = issuer_ecc_private_key.public_key()
issuer_public_bytes = issuer_public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
issuer_encoded_key = base58.b58encode(issuer_public_bytes).decode()
issuer_did_key = f"did:key:z{issuer_encoded_key}"
credential = {
    "issuer": issuer_did_key,
    "issuanceDate": "2021-01-01T00:00:00Z",
    "credentialSubject": credential_subject
}   

# Describe the credential as network access
credential["type"] = ["VerifiableCredential", "NetworkAccessCredential"]
credential["expirationDate"] = "2027-01-01T00:00:00Z"
credential["network"] = "ExampleNet"
credential["networkAccess"] = "admin"
credential["networkAccessLevel"] = "root"

# Serialize the credential to JSON
credential_json = json.dumps(credential, indent=2)
print(credential_json)

# Step 2: Serialize the credential to JSON
credential_json = json.dumps(credential, indent=2, sort_keys=True, separators=(",", ":"))  # Ensure consistent formatting

# Step 3: Compute the hash of the credential
hashed_data = hashlib.sha256(credential_json.encode()).digest()

print("🔹 Hash Before Signing:", binascii.hexlify(hashed_data).decode())

# Step 4: Sign the hash deterministically
signature = issuer_sk.sign_deterministic(hashed_data, hashfunc=hashlib.sha256, sigencode=sigencode_der)

print("Signature:", binascii.hexlify(signature))

# Step 5: Encode the signature in Base58
signature_b58 = base58.b58encode(signature).decode()

# Step 6: Update the credential with the final signature
credential["signatureValue"] = signature_b58

# Step 7: Serialize the signed credential
signed_credential_json = json.dumps(credential, indent=2, sort_keys=True, separators=(",", ":"))
print(signed_credential_json)

# Write the signed credential to a file
with open("signed_credential.json", "w") as f:
    f.write(signed_credential_json)

print("Issuer Public Key (Base58 Encoded):", issuer_encoded_key)
print("Issuer Public Key (Raw Bytes):", issuer_public_bytes.hex())

print("Signing JSON Hash:", hashlib.sha256(credential_json.encode()).hexdigest())




