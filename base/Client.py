import requests
import base64
import json
from Crypto.PublicKey import RSA
from base import Utilities
from base import ClientKeysManagement as KEYS



session = requests.Session()
BASE_URL = "http://127.0.0.1:8000/"


def generateCertificaat(name, national_code):
    """ Set national code & name in data dic"""
    data = {
        "national_code": national_code,
        "name": name,
        "timestamp" : Utilities.create_timestamp_for_payload()
    }


    """ LOAD RSA Keys """
    CA_RSA_Key = RSA.import_key(KEYS.load_public_key('CA-public.key'))
    # print(CA_RSA_Key)

    """ Send Request to CA """
    try:
        response = sendRequest(data=data, RSA_KEY=CA_RSA_Key, path="generate-certificaat")
        if response.get('status') == 'successful':
            myPrivateKey = response.get('private_key')
            myPublicKey = response.get('public_key')
            lifeTime = response.get('life_time')
            timestamp = response.get('time_stamp')
            signature = base64.b64decode(response.get('certificate_signature').encode('ascii'))

            if Utilities.check_payload_timestamp(timestamp) == False:
                print("گواهی دریافت شده تازه نمیباشد")
                return
            if Utilities.verify_certificate(national_code = national_code,public_key=myPublicKey,signature=signature,pubkey=CA_RSA_Key,lifeTime = lifeTime):
                if Utilities.check_payload_lifetime(lifeTime) == False:
                    print("گواهی ارسال شده منقصی شده است")
                    return
                print("گواهی دریافت شده و به درستی توسط ca امضا شده است. همچنین تاریخ انقضای آن فرا نرسیده است")
                KEYS.save_certificate_signature(response.get('certificate_signature'))
                KEYS.save_my_keys(privateKey=myPrivateKey, publicKey=myPublicKey)

    except Exception as e:
        print(e)


def sendRequest(data, RSA_KEY, path):

    """ Generate Session Key"""
    Session_Key = Utilities.generate_Fernet_key()
    """ Encrypt Data with Session Key"""
    encryptedData = Utilities.payload_encryptor_Fernet(data, Session_Key)
    stringSession_Key = str(Session_Key, 'utf-8')
    encryptedSessionKey = Utilities.payload_encryptor_RSA(stringSession_Key, RSA_KEY.publickey())
    encryptedSessionKey = base64.b64encode(encryptedSessionKey)

    """ Create payload """
    payload = {"data": encryptedData, "sessionKey": encryptedSessionKey}

    """ Send Request """
    try:
        response = session.post(url=BASE_URL + path, data=payload)
        response = response.json()
        return decodeResponse(response, RSA_KEY, Session_Key)
    except Exception as e:
        print("#Exception in REQUEST: {}".format(e))

def decodeResponse(response, RSA_KEY, Session_Key):
    data = response.get("data")
    data = Utilities.payload_decryptor_Fernet(data, Session_Key)
    return data

# from base import Client as c
# c.generateCertificaat(name="xana", national_code="9075529379")
generateCertificaat(name="xana", national_code="9075529379")


