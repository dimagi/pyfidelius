import base64
import os

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

from fastecdsa import keys, curve, encoding
from fastecdsa.point import Point


# Java's Bouncycastle version of the curve 25519
#   Only difference is between BC and fastcecdsa is curve.gy
#   See https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/crypto/ec/CustomNamedCurves.java#L99
#   See the same file in below commit to find the hex decoded value of gx and gy
#   https://github.com/bcgit/bc-java/commit/baefa5e3417c83299aa91be528aed6c23e23474c
BC25519 = curve.Curve(
    'BC25519',
    curve.W25519.p,
    curve.W25519.a,
    curve.W25519.b,
    curve.W25519.q,
    curve.W25519.gx,
    0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9,
    b'\x01\x03\x06\x01\x04\x01\x97U\x05\x01'
)

FC25519 = curve.Curve(
    'FC25519',
    0x7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc,
    curve.W25519.a,
    curve.W25519.b,
    curve.W25519.q,
    curve.W25519.gx,
    0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9,
    b'\x01\x03\x06\x01\x04\x01\x97U\x05\x01'
)


class KeyMaterial:
    def __init__(self, private_key, public_key, x509_public_key, nonce):
        self.private_key = private_key
        self.public_key = public_key
        self.x509_public_key = x509_public_key
        self.nonce = nonce

    @classmethod
    def generate(cls):
        private_key, public_key = keys.gen_keypair(BC25519)
        return cls._encode(private_key, public_key)

    @classmethod
    def generate_for_private_key(cls, private_key: int):
        public_key = keys.get_public_key(private_key, BC25519)
        return cls._encode(private_key, public_key)

    @classmethod
    def _encode(cls, private_key: int, public_key: Point):
        private_key_base64 = cls.encode_private_key_to_base64(private_key)
        public_key_base64 = cls.encode_public_key_to_base64(public_key)
        x509_public_key_base64 = cls.encode_x509_public_key_to_base64(public_key)
        nonce_base64 = cls.generate_base64_nonce()
        return cls(private_key_base64, public_key_base64, x509_public_key_base64, nonce_base64)

    @classmethod
    def encode_private_key_to_base64(cls, key: int):
        return base64.b64encode(
            key.to_bytes(
                (key.bit_length() + 7) // 8, byteorder='big'
            )
        ).decode('utf-8')

    @classmethod
    def encode_public_key_to_base64(cls, key: Point):
        x_bytes = key.x.to_bytes((key.x.bit_length() + 7) // 8, byteorder='big')
        y_bytes = key.y.to_bytes((key.y.bit_length() + 7) // 8, byteorder='big')
        return base64.b64encode(
            # 04 indicates uncompressed form
            b'\x04' + x_bytes + y_bytes
        ).decode('utf-8')

    @classmethod
    def encode_x509_public_key_to_base64(cls, key: Point):
        # return base64.b64encode(key.encode()).decode('utf-8')
        return encoding.pem.PEMEncoder().encode_public_key(key).encode()

    @classmethod
    def generate_base64_nonce(cls):
        nonce = os.urandom(32)
        return base64.b64encode(nonce).decode('utf-8')


class CryptoController:

    @classmethod
    def encrypt(cls, encryption_request):
        """
        Example Usage:
            encryption_request = {
                "sender_nonce": "",
                "requester_nonce": "",
                "sender_private_key": "",
                "requester_public_key": "",
                "string_to_encrypt": "",
            }

            controller = CryptoController()
            encrypted_string = controller.encrypt(encryption_request)
            print(encrypted_string)
        """
        sender_nonce = base64.b64decode(encryption_request["sender_nonce"])
        requester_nonce = base64.b64decode(encryption_request["requester_nonce"])

        # Calculate IV and salt from nonces
        xor_of_nonces = bytes(
            a ^ b for a, b in zip(sender_nonce, requester_nonce)
        )
        iv = xor_of_nonces[-12:]
        salt = xor_of_nonces[:20]

        shared_secret = cls.compute_shared_secret(
            encryption_request["sender_private_key"],
            encryption_request["requester_public_key"]
        )
        aes_encryption_key = cls.sha256_hkdf(salt, shared_secret, 32)
        string_bytes = encryption_request["string_to_encrypt"].encode('utf-8')

        cipher = AES.new(aes_encryption_key, AES.MODE_GCM, iv)
        encrypted_data, tag = cipher.encrypt_and_digest(string_bytes)
        return base64.b64encode(encrypted_data + tag).decode('utf-8')

    @classmethod
    def sane_encrypt(self, base64_encryption_request):
        # Similar to encrypt but takes the base64 encoded string
        #  string_to_encrypt_base64 instead of string_to_encrypt
        encryption_request = base64_encryption_request.copy()
        base64_string = encryption_request.pop('string_to_encrypt_base64')
        encryption_request["string_to_encrypt"] = base64.b64decode(
            base64_string
        ).decode()
        return self.encrypt(encryption_request)

    @classmethod
    def decrypt(cls, decryption_request):
        """
        Example Usage:

            decryption_request = {
                "sender_nonce": "",
                "requester_nonce": "",
                "requester_private_key": "",
                "sender_public_key": "",
                "encrypted_data": "",
            }
            decrypted_string = controller.decrypt(decryption_request)
            print(decrypted_string)
        """
        sender_nonce = base64.b64decode(decryption_request["sender_nonce"])
        requester_nonce = base64.b64decode(decryption_request["requester_nonce"])

        # Calculate IV and salt from nonces
        xor_of_nonces = bytes(
            a ^ b for a, b in zip(sender_nonce, requester_nonce)
        )
        iv = xor_of_nonces[-12:]
        salt = xor_of_nonces[:20]

        shared_secret = cls.compute_shared_secret(
            decryption_request["requester_private_key"],
            decryption_request["sender_public_key"]
        )
        aes_encryption_key = cls.sha256_hkdf(salt, shared_secret, 32)
        encrypted_string = base64.b64decode(decryption_request["encrypted_data"])[:-16]

        cipher = AES.new(aes_encryption_key, AES.MODE_GCM, iv)
        decrypted_string = cipher.decrypt(encrypted_string)

        return decrypted_string

    @classmethod
    def decode_base64_to_private_key(cls, encoded_key) -> int:
        key_bytes = base64.b64decode(encoded_key.encode('utf-8'))
        return int.from_bytes(key_bytes, byteorder='big')

    @classmethod
    def decode_base64_to_public_key(cls, encoded_key) -> Point:
        key_bytes = base64.b64decode(encoded_key.encode('utf-8'))
        # Ensure the key is in uncompressed form (starts with 0x04)
        if key_bytes[0] != 0x04:
            raise ValueError("Invalid public key format")
        x_bytes = key_bytes[1:33]  # 32 bytes for x-coordinate
        y_bytes = key_bytes[33:]    # 32 bytes for y-coordinate
        x = int.from_bytes(x_bytes, byteorder='big')
        y = int.from_bytes(y_bytes, byteorder='big')
        return Point(x, y, curve=BC25519)

    @classmethod
    def compute_shared_secret(cls, sender_private_key, requester_public_key):
        private_key_int = cls.decode_base64_to_private_key(sender_private_key)
        public_key_point = cls.decode_base64_to_public_key(requester_public_key)
        return KeyMaterial.encode_private_key_to_base64(
            (private_key_int * public_key_point).x
        )

    @classmethod
    def sha256_hkdf(cls, salt, initial_key_material, key_length_in_bytes):
        # Decode the initial key material from base64
        initial_key_material_bytes = base64.b64decode(initial_key_material)
        # Perform HKDF using SHA-256
        hkdf = HKDF(initial_key_material_bytes, key_length_in_bytes, salt, SHA256)
        # Generate the encryption key
        encryption_key = hkdf[:key_length_in_bytes]
        # Encode the encryption key to base64
        # encryption_key_base64 = base64.b64encode(encryption_key).decode('utf-8')
        return encryption_key
