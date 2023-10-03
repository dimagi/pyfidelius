pyFidelius
==========

This is a Python port of a Java project called Fidelius-CLI https://github.com/mgrmtech/fidelius-cli/ which has utilities to generate ECDH keys based on a custom ECDSA Curve 25519 and perform encryption and decryption. Refer to the Java project's README.md for implementation details.

This project uses the below two Python libraries to implement the 
equivalent cryptographic functionalities that the Java project implements.

1. [fastecdsa](https://github.com/AntonKueltz/fastecdsa) - this is used for generating public and private key pairs. This library implements the custom curve 25519 from the BouncyCastle Java library that Fidelius uses. The only difference being in the curve's `gy` parameter. We define a new custom curve named BC25519 with `gy` value taken from BouncyCastle.
2. [pyCryptodome](https://github.com/Legrandin/pycryptodome) - this is one of the popular cryptographic libraries, used here to perform encryption and decryption following the same process as Fidelius-CLI follows.


Installation
============

Add it as a pip-requirement in your requirements.txt and do a `pip install`.

```
fidelius @ git+https://github.com/dimagi/pyfidelius.git@master
```

Usage
=====

Generate a key pair.
--------------------

```
from fidelius import KeyMaterial

key_material = KeyMaterial.generate()
print(key_material.private_key)
print(key_material.public_key)
print(key_material.x509_public_key)
print(key_material.nonce)

```

Perform encryption.
-------------------

```
from fidelius import CryptoController, EncryptionRequest

encryption_request = EncryptionRequest(
    sender_nonce="lmXgblZwotx+DfBgKJF0lZXtAXgBEYr5khh79Zytr2Y=",
    requester_nonce="6uj1RdDUbcpI3lVMZvijkMC8Te20O4Bcyz0SyivX8Eg=",
    sender_private_key="AYhVZpbVeX4KS5Qm/W0+9Ye2q3rnVVGmqRICmseWni4=",
    requester_public_key="BAheD5rUqTy4V5xR4/6HWmYpopu5CO+KO8BECS0udNqUTSNo91TIqIIy1A4Vh+F94c+n9vAcwXU2bGcfsI5f69Y=",
    string_to_encrypt="Wormtail should never have been Potter cottage's secret keeper."
)
controller = CryptoController()
encrypted_string = controller.encrypt(encryption_request)
print(encrypted_string)
```

You can also pass string_to_encrypt_base64 instead of string_to_encrypt for encrypting base64 strings

Perform decryption.
-------------------

```
from fidelius import CryptoController, DecryptionRequest

decryption_request = DecryptionRequest(
    sender_nonce="lmXgblZwotx+DfBgKJF0lZXtAXgBEYr5khh79Zytr2Y=",
    requester_nonce="6uj1RdDUbcpI3lVMZvijkMC8Te20O4Bcyz0SyivX8Eg=",
    requester_private_key="DMxHPri8d7IT23KgLk281zZenMfVHSdeamq0RhwlIBk=",
    sender_public_key="BABVt+mpRLMXiQpIfEq6bj8hlXsdtXIxLsspmMgLNI1SR5mHgDVbjHO2A+U4QlMddGzqyEidzm1AkhtSxSO2Ahg=",
    encrypted_data="pzMvVZNNVtJzqPkkxcCbBUWgDEBy/mBXIeT2dJWI16ZAQnnXUb9lI+S4k8XK6mgZSKKSRIHkcNvJpllnBg548wUgavBa0vCRRwdL6kY6Yw=="
)
controller = CryptoController()
decrypted_string = controller.decrypt(decryption_request)
print(decrypted_string)
```
