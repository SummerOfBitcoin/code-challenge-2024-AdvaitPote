from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# DER-encoded signature bytes (example)
der_signature_bytes = bytes.fromhex("3045022100c792a465752f356ca187dc113552f6f32cc3b1499e0b16aa8bb4ab9799d237db022010733df96dafa890b039c3e4533879277024399795276e974d297e6b3352c861")
# Decode the DER-encoded signature
r, s = decode_dss_signature(der_signature_bytes)

r = hex(r)[2:]  
s = hex(s)[2:]

print(f"r: {r}")
print(f"s: {s}")
print(r+s)

# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
# from cryptography.hazmat.primitives.serialization import load_pem_public_key
# from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
# from cryptography.hazmat.primitives import serialization

# # Generate EC key pair
# private_key = ec.generate_private_key(ec.SECP256K1())
# public_key = private_key.public_key()


# public_key_der = public_key.public_bytes(
#     encoding=serialization.Encoding.DER,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# )

# # Convert DER-encoded public key to hexadecimal format
# public_key_hex = public_key_der.hex()
# # Serialize public key to PEM format (for demonstration purposes)
# public_key_pem = public_key.public_bytes(
#     Encoding.PEM,
#     PublicFormat.SubjectPublicKeyInfo
# )

# compressed_public_key = public_key.public_bytes(
#     encoding=Encoding.X962,
#     format=PublicFormat.CompressedPoint
# )
# print(compressed_public_key.hex())

# # Create a message to sign
# message = b"Hello, this is a test message"

# # Sign the message
# signature = private_key.sign(
#     message,
#     ec.ECDSA(hashes.SHA256())
# )

# print(signature.hex())

# # Verify the signature
# # try:
# #     public_key = load_pem_public_key(public_key_pem)
# #     public_key.verify(
# #         signature,
# #         message,
# #         ec.ECDSA(hashes.SHA256())
# #     )
# #     print("Signature verified successfully.")
# # except Exception as e:
# #     print("Signature verification failed.")

