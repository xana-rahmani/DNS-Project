import os
import json
from datetime import datetime
import base64
from django.http.response import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from .models import Restricted_National_Codes
from base import Utilities
from Voting_System import settings
from Crypto.PublicKey import RSA

def load_RSA_key(path):
    path = os.path.join('AS', path)
    path = os.path.join(settings.BASE_DIR, path)
    with open(path, 'r') as f:
        key_data = f.read()
    key = RSA.import_key(key_data)
    return key

@csrf_exempt
@require_http_methods(["POST"])
def generate_AS_ticket(request):
    try:
        sessionKey = Utilities.payload_decryptor_RSA(request.POST["sessionKey"], load_RSA_key('AS-private.key')).encode()
        actual_message = Utilities.payload_decryptor_Fernet(request.POST["data"], sessionKey)
        public_key = actual_message["public_key"]
        national_code = actual_message["national_code"]
        certificate_signature = actual_message["certificate_signature"]
        life_time = actual_message["lifetime"]
        timestamp = actual_message["timestamp"]
        signature = base64.b64decode(actual_message["signature"].encode('ascii'))
        if national_code is None:
            payload = {'status': 'fail', 'message': 'کدملی به درستی ارسال نشده است.'}
            return sendResponse(payload, sessionKey)
        if Utilities.check_payload_timestamp(timestamp) == False:
            payload = {'status': 'fail', 'message': 'مهلت درخواست ارسال شده منقضی شده است.'}
            return sendResponse(payload, sessionKey)
        message = json.dumps({'national_code': national_code,
                              'public_key': public_key,
                              'lifetime': life_time,
                              'certificate_signature': certificate_signature,
                              'timestamp': timestamp,
                              })
        if Utilities.verify_RSA(message,signature, RSA.import_key(public_key)) == False:
            payload = {'status': 'fail', 'message': 'امضا با کلید عمومی ارسالی مطابقت ندارد.'}
            return sendResponse(payload, sessionKey)
        if Utilities.check_payload_lifetime(life_time) == False:
            payload = {'status': 'fail', 'message': 'گواهی ارسالی منقضی شده است'}
            return sendResponse(payload, sessionKey)
        if Utilities.verify_certificate(national_code = national_code, lifeTime= life_time,public_key = public_key,
                                        signature = base64.b64decode(actual_message['certificate_signature'].encode('ascii'))
                ,pubkey=load_RSA_key('CA-public.key')) == False:
            payload = {'status': 'fail', 'message': 'گواهی ارسالی معتبر نمیباشد'}
            return sendResponse(payload, sessionKey)
    except Exception as e:
        print("#Exception-1: {}".format(e))
        payload = {'status': 'fail', 'message': 'درخواست به درستی ارسال نشده است.'}
        return sendResponse(payload, sessionKey)
    try:
        restricted_users = Restricted_National_Codes.objects.filter(national_code=national_code).count()
        if restricted_users > 0:
            payload = {'status': 'fail', 'message': 'متاسفانه شما مجاز به رای دادن نمیباشید.'}
            return sendResponse(payload, sessionKey)
        sk_voter = Utilities.generate_Fernet_key()
        # creating vote certificate
        # vote certificate consists of a session key which is encrypted with the public key of vs
        # and sk_voter || public voter || signature encrypted with session key
        session_key = Utilities.generate_Fernet_key() # session key between AS and VS
        message = json.dumps({
            'sk_voter': str(sk_voter, 'utf-8'),
            'public_key': public_key
        })
        AS_signature = base64.b64encode(Utilities.sign_RSA(message, load_RSA_key('AS-private.key'))).decode('ascii')
        data = {
            "status": "successful",
            "sk_voter": str(sk_voter, 'utf-8'),
            "public_key": public_key,
            "AS_signature": AS_signature,
        }
        encryptedData = Utilities.payload_encryptor_Fernet(data, session_key)
        stringSession_Key = str(session_key, 'utf-8')
        encryptedSessionKey = Utilities.payload_encryptor_RSA(stringSession_Key, load_RSA_key('VS-public.key'))
        encryptedSessionKey = base64.b64encode(encryptedSessionKey).decode('ascii')
        encryptedData = base64.b64encode(encryptedData).decode('ascii')
        vote_crt = json.dumps({'data': encryptedData, 'sessionKey': encryptedSessionKey})
        new_timestamp = Utilities.create_timestamp_for_payload()
        message = json.dumps({
            'status': 'successful',
             'sk_voter':str(sk_voter, 'utf-8'),
            'vote_crt' : vote_crt,
            'time_stamp': new_timestamp
        })
        AS_signature = base64.b64encode(Utilities.sign_RSA(message, load_RSA_key('AS-private.key'))).decode('ascii')
        payload = {
            'status': 'successful',
            'sk_voter':str(sk_voter, 'utf-8'),
            'vote_crt' : vote_crt,
            'time_stamp': new_timestamp,
            'signature' : AS_signature
        }
        return sendResponse(payload,sessionKey)
    except Exception as e:
        print("#Exception2: {}".format(e))
        payload = {'status': 'fail', 'message': 'لطفا با پشتیبانی تماس بگیرید.'}
        return sendResponse(payload, sessionKey)
def sendResponse(data, key):

    """ Encrypt Data with Session Key"""
    encryptedData = Utilities.payload_encryptor_Fernet(data, key)
    encryptedData = encryptedData.decode('utf-8')
    """ Return Response """
    return JsonResponse({"data": encryptedData}, status=200)