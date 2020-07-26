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


def generateCertificaat(name, national_code):
    """ Set national code & name in  data dic"""
    data = {
        "national_code": national_code,
        "name": name
    }

    """ LOAD RSA Keys """
    CA_RSA_Key = RSA.import_key(load_public_key('CA-public.key'))

    """ Send Request to CA """
    response = sendRequest(data=data, RSA_KEY=CA_RSA_Key, path="generate-certificaat")
    print(response.json())


def sendRequest(data, RSA_KEY, path):

    """ Generate Session Key"""
    Session_Key = Utilities.generate_Fernet_key()

    """ Encrypt Data with Session Key"""
    encryptedData = Utilities.payload_encryptor_Fernet(data, Session_Key)
    Session_Key = str(Session_Key, 'utf-8')
    encryptedSessionKey = Utilities.payload_encryptor_RSA(Session_Key, RSA_KEY.publickey())
    encryptedSessionKey = base64.b64encode(encryptedSessionKey)

    """ Create payload """
    payload = {"data": encryptedData, "sessionKey": encryptedSessionKey}
    # print(payload)
    """ Send Request """
    response = session.post(url=BASE_URL + path, data=payload)
    return response


generateCertificaat(name="xana", national_code="9075529379")
# from base import Client
