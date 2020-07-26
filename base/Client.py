import requests
import os
from base import Utilities
import base64
from Crypto.PublicKey import RSA


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
Public_Keys_DIR = os.path.join(BASE_DIR, 'base/Public-Keys')


def load_public_key(path):
    path = os.path.join(Public_Keys_DIR, path)
    with open(path, 'r') as f:
        key = f.read()
    return key


session = requests.Session()
BASE_URL = "http://127.0.0.1:8000/"


def generateCertificaat():
    data = {
        "national_code": "1055219379",
        "name": "xana"
    }
    key = RSA.import_key(load_public_key('CA-public.key'))
    encrypted = Utilities.payload_encryptor(data, key)
    # print(base64.b64encode(encrypted))

    payload = {"data": base64.b64encode(encrypted)}
    response = session.post(url=BASE_URL + "generate-certificaat", data=payload)
    print(response.json())
    return response