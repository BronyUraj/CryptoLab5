from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def generate_keypair(public_exponent=65537, key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
    return private_key, private_key.public_key()


def sign_message(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_sign(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return "Signature is valid!"
    except InvalidSignature:
        return "Signature is invalid!"


def RSA_Showcase():
    private_key, public_key = generate_keypair()
    print(
        f"p = {private_key.private_numbers().p}\nq = {private_key.private_numbers().q}\nd = {private_key.private_numbers().d}")
    print(f"n = {public_key.public_numbers().n}\ne = {public_key.public_numbers().e}")
    message = b"Hello World!"
    signature = sign_message(private_key, message)
    print(f"Message = {message.decode()}\nSignature = {signature.hex()}")
    print(verify_sign(public_key, message, signature))
    print(verify_sign(public_key, message + b"Uga-Buga", signature))
