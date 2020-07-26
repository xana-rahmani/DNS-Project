import requests
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
Public_Keys_DIR = os.path.join(BASE_DIR, 'Public-Keys')


def load_public_key(path):
    print("load_public_key")
    path = os.path.join(Public_Keys_DIR, path)
    with open(path, 'r') as f:
        key = f.read()
    return key


session = requests.Session()
BASE_URL = "http://127.0.0.1:8000/"

print(load_public_key('CA-public.key'))

def generateCertificaat():
    payload = {
        "national_code": "1055219379",
        "name": "xana"
    }
    response = session.post(url=BASE_URL + "generate-certificaat", data=payload)
    print(response)
    return response