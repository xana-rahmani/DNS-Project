import os
# use pip install pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256


def generate_key():
    return RSA.generate(1024, os.urandom)


def encrypt(message, pubKey):
    encryptor = PKCS1_OAEP.new(pubKey)
    encrypted = encryptor.encrypt(message.encode("utf-8"))
    return encrypted


def decrypt(message, keypair):
    decryptor = PKCS1_OAEP.new(keypair)
    decrypted = decryptor.decrypt(message)
    return decrypted


def sign(message, keypair):
    h = SHA256.new()
    h.update(message.encode("utf_8"))
    signer = PKCS1_v1_5.new(keypair)
    signature = signer.sign(h)
    return signature


def verify(message, signature, pubkey):
    signer = PKCS1_v1_5.new(pubkey)
    h = SHA256.new()
    h.update(message.encode("utf_8"))
    return signer.verify(h, signature)






