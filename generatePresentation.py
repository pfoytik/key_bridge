import json
import base58
import hashlib
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat

# Step 1: Load the Holder's Private Key
with open("certs/Holder_ecc_private_key.pem", "rb") as f:
    holder_ecc_private_key = serialization.load_pem_private_key(f.read(), password=None)

# Step 2: Load the Verifiable Credential
with open("signed_credential.json", "r") as f:
    credential = json.load(f)

# Step 3: Get Holder’s Public Key (for DID)
holder_public_key = holder_ecc_private_key.public_key()
holder_private_key_numbers = holder_ecc_private_key.private_numbers()
holder_private_key_bytes = holder_private_key_numbers.private_value.to_bytes(32, byteorder="big")
holder_sk = SigningKey.from_string(holder_private_key_bytes, curve=SECP256k1)

holder_public_bytes = holder_public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
holder_encoded_key = base58.b58encode(holder_public_bytes).decode()
holder_did_key = f"did:key:z{holder_encoded_key}"

# Step 4: Create the Presentation Object (without proof)
presentation = {
    "verifiableCredential": [credential],
    "holder": holder_did_key
}

# Step 5: Serialize the Presentation (ensure deterministic format)
presentation_json = json.dumps(presentation, indent=2, separators=(",", ":"))

# Step 6: Compute SHA-256 Hash of the Presentation
digest = hashes.Hash(hashes.SHA256())
digest.update(presentation_json.encode())
hashed_data = digest.finalize()

# Step 7: Sign the Hash using the Holder’s Private Key
signature = holder_sk.sign_deterministic(hashed_data, hashfunc=hashlib.sha256, sigencode=sigencode_der)

# Step 8: Encode the Signature in Base58
signature_b58 = base58.b58encode(signature).decode()

# Step 9: Attach Proof to the Presentation
presentation["proof"] = {
    "type": "EcdsaSecp256k1Signature2019",
    "created": "2025-03-19T00:00:00Z",
    "proofPurpose": "authentication",
    "verificationMethod": holder_did_key,
    "signatureValue": signature_b58
}

# Step 10: Save `presentation.json`
with open("certs/presentation.json", "w") as f:
    json.dump(presentation, f, indent=2, separators=(",", ":"))

print("✅ Presentation successfully created!")
print(json.dumps(presentation, indent=2))
