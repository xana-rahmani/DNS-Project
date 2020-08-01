import requests
import base64
import json
import logging
from Crypto.PublicKey import RSA
from base import Utilities
from base import ClientKeysManagement as KEYS


session = requests.Session()
BASE_URL = "http://127.0.0.1:8000/"


def generateCertificaat(name, national_code):
    logging.info("\n\n\t\t---- Client: generateCertificaat -----\n")

    """ Set national code & name in data dic"""
    data = {
        "national_code": national_code,
        "name": name,
        "timestamp": Utilities.create_timestamp_for_payload()
    }
    logging.info("Sending Data: ", data)

    """ LOAD RSA Keys """
    CA_RSA_Key = RSA.import_key(KEYS.load_public_key('CA-public.key'))

    """ Send Request to CA """
    try:
        response = sendRequest(data=data, RSA_KEY=CA_RSA_Key, path="generate-certificaat")
        if response.get('status') == 'successful':
            myPrivateKey = response.get('private_key')
            myPublicKey = response.get('public_key')
            lifeTime = response.get('life_time')
            timestamp = response.get('time_stamp')
            signature = base64.b64decode(response.get('certificate_signature').encode('ascii'))
            if not Utilities.check_payload_timestamp(timestamp):
                message = "گواهی دریافت شده تازه نمیباشد."
                print(message)
                logging.info(message)
                return
            if Utilities.verify_certificate(national_code=national_code,public_key=myPublicKey, signature=signature, pubkey=CA_RSA_Key, lifeTime=lifeTime):
                if not Utilities.check_payload_lifetime(lifeTime):
                    message = "گواهی ارسال شده منقصی شده است."
                    print(message)
                    logging.info(message)
                    return
                message = "گواهی دریافت شده و به درستی توسط ca امضا شده است. همچنین تاریخ انقضای آن فرا نرسیده است."
                print(message)
                logging.info(message)
                KEYS.save_certificate_signature(response.get('certificate_signature'))
                KEYS.save_certificate_lifeTime(response.get('life_time'))
                KEYS.save_my_keys(privateKey=myPrivateKey, publicKey=myPublicKey)
        else:
            message = response.get("message")
            print(message)
            logging.info(message)
    except Exception as e:
        message = "Exception #1: {}".format(e)
        print(message)
        logging.info(message)


def generate_AS_ticket(national_code):
    logging.info("\n\n\t\t---- Client: generate_AS_ticket -----\n")
    private_key, public_key = KEYS.read_my_keys()
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
        "signature": signature
    }
    logging.info("Sending Data: ", data)
    """ LOAD RSA Key of AS """
    AS_RSA_Key = RSA.import_key(KEYS.load_public_key('AS-public.key'))

    """ Send Request to AS """
    try:
        response = sendRequest(data=data, RSA_KEY=AS_RSA_Key, path="generate-AS-ticket")
        if response.get('status') == 'successful':
            sk_voter = response.get('sk_voter')
            vote_crt = response.get('vote_crt')
            timestamp = response.get('time_stamp')
            signature = base64.b64decode(response.get('signature').encode('ascii'))
            if not Utilities.check_payload_timestamp(timestamp):
                message = "گواهی دریافت شده تازه نمیباشد."
                print(message)
                logging.info(message)
                return
            message = json.dumps({
                'status': 'successful',
                'sk_voter': sk_voter,
                'vote_crt': vote_crt,
                'time_stamp': timestamp
            })
            if not Utilities.verify_RSA(message, signature, AS_RSA_Key):
                message = "جواب دریافت شده معتبر نمیباشد."
                print(message)
                logging.info(message)
                return
            message = "بلیت و کلید رای دهی دریافت شد. برای اطمینان از کارکرد آن لطفاً اقدام به رای دهی نمایید."
            print(message)
            logging.info(message)
            KEYS.save_voting_certificate(vote_crt)
            KEYS.save_voting_secret_key(sk_voter)
        else:
            message = response.get('message')
            print(message)
            logging.info(message)
    except Exception as e:
        message = "Exception #2: {}".format(e)
        print(message)
        logging.info(message)


def vote(candidate_id):
    logging.info("\n\n\t\t---- Client: Vote -----\n")

    private_key, public_key = KEYS.read_my_keys()
    vote_crt = KEYS.read_voting_certificate()
    sk_voter = KEYS.read_voting_secret_key()
    signature = base64.b64encode(Utilities.sign_RSA(str(candidate_id), RSA.import_key(private_key))).decode('ascii')
    voting_data = {
        'vote': str(candidate_id),
        'signature': signature
    }
    logging.info("Voting Data: ", voting_data)
    voting_data = Utilities.payload_encryptor_Fernet(voting_data, sk_voter)
    payload = {
        "data": voting_data.decode('utf-8'),
        "vote_crt": vote_crt
    }
    logging.info("Sending Data: ", payload)

    """ LOAD RSA Key of AS """
    VS_RSA_Key = RSA.import_key(KEYS.load_public_key('VS-public.key'))
    try:
        response = sendRequest(data=payload, RSA_KEY=VS_RSA_Key, path="vote")
        message = response.get('message')
        print(message)
        logging.info(message)
    except Exception as e:
        message = "Exception #3: {}".format(e)
        print(message)
        logging.info(message)


def seeVote():
    logging.info("\n\n\t\t---- Client: See Vote -----\n")
    response = session.get(url=BASE_URL + "seeVote")
    response = response.json()
    for i in response:
        message = "Candidate ID: {}\t num Vote: {}".format(i, response.get(i))
        print(message)
        logging.info(message)


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
        message = "#Exception in REQUEST: {}".format(e)
        print(message)
        logging.info(message)


def decodeResponse(response, RSA_KEY, Session_Key):
    try:
        data = response.get("data")
        data = Utilities.payload_decryptor_Fernet(data, Session_Key)
    except Exception as e:
        message = "#Exception in Decode Response: {}".format(e)
        print(message)
        logging.info(message)
    return data
