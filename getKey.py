from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ec import SECP256K1


# Load the private key from the PEM file
with open("private_key.pem", "rb") as f:
    private_key = load_pem_private_key(f.read(), password=None)

# Ensure the private key is of the ECC type (secp256k1 in this case)
if not hasattr(private_key, "private_numbers"):
    raise ValueError("The provided key is not an ECC private key")

if not isinstance(private_key.curve, SECP256K1):
    raise ValueError("The private key is not using the SECP256K1 curve")


# Extract the private value as an integer
private_value = private_key.private_numbers().private_value

# Convert the private value to a 32-byte hexadecimal string
hex_private_key = format(private_value, '064x')  # Ensure it is 64 characters (32 bytes)
print(f"32-byte hex private key: {hex_private_key}")

