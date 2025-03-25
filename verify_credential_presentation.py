import json
import base58
import hashlib
import binascii
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError, util
from ecdsa.ellipticcurve import Point
from ecdsa.util import sigdecode_der

# Load the presentation JSON
with open("certs/presentation.json", "r") as f:
    presentation = json.load(f)

### 1️⃣ Verify the Verifiable Credential Signature (Issuer) ###
credential = presentation["verifiableCredential"][0]
pres_sig = presentation["proof"]["signatureValue"]

### get the did of the holder
holder_public = presentation["holder"]

# Extract holder DID and decode public key
holder_did = holder_public  # Example: "did:key:zfLFs5X..."
print(holder_did)
holder_encoded_key = holder_did[9:]
print(holder_encoded_key)
holder_compressed_key = base58.b58decode(holder_encoded_key)

### verify the signature with the holder's public key
try:
    holder_vk = VerifyingKey.from_string(holder_compressed_key, curve=SECP256k1)
    print("✅ Successfully loaded VerifyingKey from uncompressed public key")
except Exception as e:
    print("❌ Failed to convert key:", e)

# Extract issuer DID and decode public key
issuer_did = credential["issuer"]  # Example: "did:key:zfLFs5X..."
print(issuer_did)
issuer_encoded_key = issuer_did[9:]
print(issuer_encoded_key)
issuer_compressed_key = base58.b58decode(issuer_encoded_key)

# Debugging: Print key details
print(f"Issuer Encoded Key Length: {len(issuer_compressed_key)}")
print(f"Issuer Encoded Key (Hex): {issuer_compressed_key.hex()}")

# Convert to VerifyingKey
try:
    issuer_vk = VerifyingKey.from_string(issuer_compressed_key, curve=SECP256k1)
    print("✅ Successfully loaded VerifyingKey from uncompressed public key")
except Exception as e:
    print("❌ Failed to convert key:", e)

# Extract and decode the credential signature
vc_signature_b58 = credential["signatureValue"]
vc_signature_der = base58.b58decode(vc_signature_b58)

#print("DER Encoded Signature:", binascii.hexlify(signature))
print("Base58 Encoded Signature:", vc_signature_b58)
print("Decoded Signature:", binascii.hexlify(vc_signature_der))


# Ensure JSON encoding matches exactly the signing process
credential_copy = credential.copy()
del credential_copy["signatureValue"]  # Remove signature before hashing
credential_json = json.dumps(credential_copy, indent=2, sort_keys=True, separators=(",", ":"))
vc_hashed_data = hashlib.sha256(credential_json.encode()).digest()

print("🔹 Hash Before Verifying:", binascii.hexlify(vc_hashed_data).decode())

# Verify the signature
try:
    issuer_vk.verify(vc_signature_der, vc_hashed_data, hashfunc=hashlib.sha256, sigdecode=sigdecode_der)
    print("✅ Issuer Credential Signature Verified!")
except BadSignatureError:
    print("❌ Issuer Signature Verification Failed!")

issuer_vk_compressed = issuer_vk.to_string("compressed")
print("Issuer Public Key Used for Verification (Base58 Encoded):", base58.b58encode(issuer_vk_compressed).decode())
print("Issuer Public Key Used for Verification (Raw Bytes):", issuer_vk_compressed.hex())

#print("Verification JSON:", credential_json)
#print("Verification JSON Hash:", hashlib.sha256(credential_json.encode()).hexdigest())


