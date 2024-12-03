from cryptography.hazmat.primitives.serialization import load_pem_private_key
import binascii

# Load the private key from the PEM file
with open("private_key.pem", "rb") as f:
    private_key = load_pem_private_key(f.read(), password=None)

# Ensure the private key is of the ECC type
if not hasattr(private_key, "curve"):
    raise ValueError("The provided key is not an ECC private key")

# Check if the curve is SECP256R1 (P-256)
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
if not isinstance(private_key.curve, SECP256R1):
    raise ValueError("The private key is not using the P-256 curve")

# Extract the private value as an integer
private_value = private_key.private_numbers().private_value

# Convert the private value to a 32-byte hexadecimal string
hex_private_key = format(private_value, '064x')  # Ensure it is 64 characters (32 bytes)
private_key_bytes = private_value.to_bytes(32, byteorder="big")

print(f"32-byte hex private key: {hex_private_key}")
print(f"32-byte private key (bytes): {binascii.hexlify(private_key_bytes).decode()}")

