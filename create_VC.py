import json
import base58
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
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

# Sign the credential with the issuer's private key
issuer_private_key = issuer_ecc_private_key
signature = issuer_private_key.sign(
    credential_json.encode(),
    ec.ECDSA(hashes.SHA256())
)

# Encode the signature in Base58
signature_b58 = base58.b58encode(signature).decode()
print(f"Signature: {signature_b58}")

# Add the signature to the credential
credential["proof"] = {
    "type": "secp256k1",
    "created": "2021-01-01T00:00:00Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": issuer_did_key,
    "signatureValue": signature_b58
}

# Serialize the signed credential to JSON
signed_credential_json = json.dumps(credential, indent=2)
print(signed_credential_json)

# Write the signed credential to a file
with open("signed_credential.json", "w") as f:
    f.write(signed_credential_json)
# Output:
# {
#   "issuer": "did:key:zH2wW7Q5hF3J
#   "issuanceDate": "2021-01-01T00:00:00Z",
#   "credentialSubject": {
#     "id": "did:key:zH2wW7Q5hF3J"
#   },
#   "type": [
#     "VerifiableCredential",
#     "NetworkAccessCredential"
#   ],
#   "expirationDate": "2027-01-01T00:00:00Z",
#   "network": "ExampleNet",
#   "networkAccess": "admin",
#   "networkAccessLevel": "root"
# }
# Signature: 3Gz3W9zX8yj5
# {
#   "issuer": "did:key:zH2wW7Q5hF3J",
#   "issuanceDate": "2021-01-01T00:00:00Z",
#   "credentialSubject": {
#     "id": "did:key:zH2wW7Q5hF3J"
#   },
#   "type": [
#     "VerifiableCredential",
#     "NetworkAccessCredential"
#   ],
#   "expirationDate": "2027-01-01T00:00:00Z",
#   "network": "ExampleNet",
#   "networkAccess": "admin",
#   "networkAccessLevel": "root",
#   "proof": {
#     "type": "secp256k1",
#     "created": "2021-01-01T00:00:00Z",
#     "proofPurpose": "assertionMethod",
#     "verificationMethod": "did:key:zH
#     "signatureValue": "3Gz3W9zX8yj5"
#   }
# }
#






