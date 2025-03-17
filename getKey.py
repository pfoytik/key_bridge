from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa, ec

### read args from command line
import argparse
pk_path = argparse.ArgumentParser()
pk_path.add_argument("private_key_path", help="Path to the private key file")
args = pk_path.parse_args()
private_key_path = args.private_key_path

# Load the private key from the PEM file
with open(private_key_path, "rb") as f:
    private_key = load_pem_private_key(f.read(), password=None)

# Check if the key is ECC or RSA
if isinstance(private_key, ec.EllipticCurvePrivateKey):
    # ECC Key Handling
    private_numbers = private_key.private_numbers()
    hex_private_key = format(private_numbers.private_value, '064x')
    print(f"ECC 32-byte hex private key: {hex_private_key}")

elif isinstance(private_key, rsa.RSAPrivateKey):
    # RSA Key Handling (extract private exponent `d`)
    private_numbers = private_key.private_numbers()
    hex_private_key = format(private_numbers.d, 'x')  # RSA private exponent
    print(f"RSA private key (d): {hex_private_key}")

else:
    raise ValueError("Unsupported key type")
