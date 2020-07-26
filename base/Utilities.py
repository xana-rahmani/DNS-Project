import os
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256


def generate_key():
    key = RSA.generate(1024, os.urandom)
    private_key = key.exportKey()
    public_key = key.publickey().exportKey()
    return private_key.decode('ascii'), public_key.decode('ascii')


def encrypt(message, pubKey):
    encryptor = PKCS1_OAEP.new(pubKey)
    encrypted = encryptor.encrypt(message.encode("utf-8"))
    return encrypted


def decrypt(message, keypair):
    decryptor = PKCS1_OAEP.new(keypair)
    decrypted = decryptor.decrypt(message)
    return decrypted.decode('utf-8')


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


def payload_encryptor(payload, pubkey):
    message = json.dumps(payload)
    encrypted_message = encrypt(message, pubkey)
    return encrypted_message


def payload_decryptor(message, keypair):
    message = bytes(message, 'utf-8')
    message = base64.b64decode(message)
    decrypted_message = decrypt(message, keypair)
    try:
        actual_payload = json.loads(decrypted_message) or {}
    except:
        return {}
    return actual_payload
