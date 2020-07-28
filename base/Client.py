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
                KEYS.save_certificate_lifeTime(response.get('life_time'))
                KEYS.save_my_keys(privateKey=myPrivateKey, publicKey=myPublicKey)

    except Exception as e:
        print(e)
def generate_AS_ticket(national_code):
    private_key,public_key = KEYS.read_my_keys()
    certificate_signature = KEYS.read_certificate_signature()
    lifetime = KEYS.read_certificate_lifeTime()
    timestamp = Utilities.create_timestamp_for_payload()
    message = json.dumps({
        'national_code': national_code,
        'public_key': public_key,
        'lifetime': lifetime,
        'certificate_signature': certificate_signature,
        'timestamp': timestamp,
    })
    signature = base64.b64encode(Utilities.sign_RSA(message, RSA.import_key(private_key))).decode('ascii')
    data = {
        "national_code": national_code,
        "public_key": public_key,
        "lifetime": lifetime,
        "certificate_signature": certificate_signature,
        "timestamp": timestamp,
        "signature":signature
    }
    """ LOAD RSA Key of AS """
    AS_RSA_Key = RSA.import_key(KEYS.load_public_key('AS-public.key'))
    # print(CA_RSA_Key)

    """ Send Request to AS """
    try:
        response = sendRequest(data=data, RSA_KEY=AS_RSA_Key, path="generate-AS-ticket")
        if response.get('status') == 'successful':
            sk_voter = response.get('sk_voter')
            vote_crt = response.get('vote_crt')
            timestamp = response.get('time_stamp')
            signature = base64.b64decode(response.get('signature').encode('ascii'))

            if Utilities.check_payload_timestamp(timestamp) == False:
                print("گواهی دریافت شده تازه نمیباشد")
                return
            message = json.dumps({
                'status': 'successful',
                'sk_voter': sk_voter,
                'vote_crt': vote_crt,
                'time_stamp': timestamp
            })
            if Utilities.verify_RSA(message,signature,AS_RSA_Key) == False:
                print("جواب دریافت شده معتبر نمیباشد")
                return
            print("بلیت و کلید رای دهی با موفقیت دریافت شد. برای اطمینان از کارکرد آن ها لطفاً اقدام به رای دهی نمایید")
            KEYS.save_voting_certificate(vote_crt)
            KEYS.save_voting_secret_key(sk_voter)
    except Exception as e:
        print(e)
def vote(candidate_id):
    private_key, public_key = KEYS.read_my_keys()
    vote_crt = KEYS.read_voting_certificate()
    return

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
generate_AS_ticket(national_code="9075529379")
vote(candidate_id=1)


