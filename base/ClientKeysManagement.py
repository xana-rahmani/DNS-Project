import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
Public_Keys_DIR = os.path.join(BASE_DIR, 'base/Public-Keys')
Client_Keys_DIR = os.path.join(BASE_DIR, 'base/ClientKeys')


def load_public_key(path):
    path = os.path.join(Public_Keys_DIR, path)
    with open(path, 'r') as f:
        key = f.read()
    return key

def save_my_keys(privateKey=None, publicKey=None):
    try:
        if privateKey:
            with open(Client_Keys_DIR + "/myPrivateKey.key", 'w') as f:
                f.write(privateKey)
        if publicKey:
            with open(Client_Keys_DIR + "/myPublicKey.key", 'w') as f:
                f.write(publicKey)
    except Exception as e:
        print("Exception in Write MY Keys: {}".format(e))
def save_certificate_signature(signature):
    try:
        with open(Client_Keys_DIR + "/myCertificateSignature.txt", 'w') as f:
            f.write(signature)
    except Exception as e:
        print("Exception in Write MY Keys: {}".format(e))
def read_certificate_signature():
    with open(Client_Keys_DIR + "/myCertificateSignature.txt", 'w') as f:
        certificate_signature = f.read()
    return certificate_signature

def read_my_keys():
    try:
        with open(Client_Keys_DIR + "/myPrivateKey.key", 'w') as f:
            privateKey = f.read()
        with open(Client_Keys_DIR + "/myPublicKey.key", 'w') as f:
            publicKey = f.read()
        return privateKey, publicKey
    except Exception as e:
        print("Exception in Read MY Keys: {}".format(e))