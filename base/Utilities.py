import os
import json
from datetime import datetime
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from cryptography.fernet import Fernet


def generate_RSA_key():
    key = RSA.generate(1024, os.urandom)
    private_key = key.exportKey()
    public_key = key.publickey().exportKey()
    return private_key.decode('ascii'), public_key.decode('ascii')


def encrypt_RSA(message, pubKey):
    encryptor = PKCS1_OAEP.new(pubKey)
    encrypted = encryptor.encrypt(message.encode("utf-8"))
    return encrypted


def decrypt_RSA(message, keypair):
    decryptor = PKCS1_OAEP.new(keypair)
    decrypted = decryptor.decrypt(message)
    return decrypted.decode('utf-8')


def sign_RSA(message, keypair):
    h = SHA256.new()
    h.update(message.encode("utf_8"))
    signer = PKCS1_v1_5.new(keypair)
    signature = signer.sign(h)
    return signature


def verify_RSA(message, signature, pubkey):
    signer = PKCS1_v1_5.new(pubkey)
    h = SHA256.new()
    h.update(message.encode("utf_8"))
    return signer.verify(h, signature)


def verify_certificate(national_code, public_key, signature, pubkey, lifeTime):
    message = json.dumps(
        {
            'national_code': national_code,
            'public_key': public_key,
            'life_time': lifeTime
        })
    return verify_RSA(message, signature, pubkey)


def verify_vote(candidate_id, pubkey, signature):
    return verify_RSA(candidate_id, signature, pubkey)


def verify_AS_sign(sk_voter, public_key, pubkey, signature):
    message = json.dumps(
        {
            'sk_voter': sk_voter,
            'public_key': public_key,
        })
    return verify_RSA(message, signature, pubkey)


def payload_encryptor_RSA(payload, pubkey):
    message = json.dumps(payload)
    encrypted_message = encrypt_RSA(message, pubkey)
    return encrypted_message


def payload_decryptor_RSA(message, keypair):
    message = bytes(message, 'utf-8')
    message = base64.b64decode(message)
    decrypted_message = decrypt_RSA(message, keypair)
    try:
        actual_payload = json.loads(decrypted_message) or {}
    except Exception as e:
        return {}
    return actual_payload


"""     Fernet       """


def generate_Fernet_key():
    key = Fernet.generate_key()
    return key


def encrypt_Fernet(message, key):
    f = Fernet(key)
    message = message.encode()
    encrypted = f.encrypt(message)
    return encrypted


def payload_encryptor_Fernet(payload, key):
    message = json.dumps(payload)
    encrypted_message = encrypt_Fernet(message, key)
    return encrypted_message


def decrypt_Fernet(message, key):
    f = Fernet(key)
    decrypted = f.decrypt(message).decode('utf-8')
    return decrypted


def payload_decryptor_Fernet(message, key):
    if not isinstance(message, bytes):
        message = bytes(message, 'utf-8')
    decrypted_message = decrypt_Fernet(message, key)
    try:
        actual_payload = json.loads(decrypted_message) or {}
    except:
        return {}
    return actual_payload


"""     Timestamp       """


def create_timestamp_for_payload():
    return datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')


def create_lifetime_for_payload():
    import datetime as dt
    lifeTime = datetime.now() + dt.timedelta(365)
    return lifeTime.strftime('%Y-%m-%dT%H:%M:%S.%f')


def check_payload_timestamp(timestamp):
    real_time = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f')
    now = datetime.now()
    difference = (now - real_time).total_seconds()
    if difference <= 5:
        return True
    return False


def check_payload_lifetime(life_time):
    real_time = datetime.strptime(life_time, '%Y-%m-%dT%H:%M:%S.%f')
    now = datetime.now()
    difference = (now - real_time).total_seconds()
    if difference < 0:
        return True
    return False



