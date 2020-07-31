import os
import json
from datetime import datetime
import base64
from django.http.response import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from .models import Candidates,Votes
from base import Utilities
from Voting_System import settings
from Crypto.PublicKey import RSA


def load_RSA_key(path):
    path = os.path.join('VS', path)
    path = os.path.join(settings.BASE_DIR, path)
    with open(path, 'r') as f:
        key_data = f.read()
    key = RSA.import_key(key_data)
    return key


@csrf_exempt
@require_http_methods(["POST"])
def vote(request):
    try:
        sessionKey = Utilities.payload_decryptor_RSA(request.POST["sessionKey"], load_RSA_key('VS-private.key')).encode()
        actual_message = Utilities.payload_decryptor_Fernet(request.POST["data"], sessionKey)
        vote_crt = actual_message.get("vote_crt")
        vote_crt = json.loads(vote_crt)
        AS_sessionKey = Utilities.payload_decryptor_RSA(vote_crt.get('sessionKey'), load_RSA_key('VS-private.key'))

        vote_crt_data = vote_crt.get('data')
        vote_crt_data = vote_crt_data.encode('ascii')
        vote_crt_data = base64.b64decode(vote_crt_data)

        print("*** vote_crt_data1: ", vote_crt_data)
        vote_crt_data = Utilities.payload_decryptor_Fernet(vote_crt_data, AS_sessionKey.encode())
        print("*** vote_crt_data2: ", vote_crt_data)
        vote = request.Post["data"]
    except Exception as e:
        print("#Exception-1: {}".format(e))
        payload = {'status': 'fail', 'message': 'درخواست به درستی ارسال نشده است.'}
        # return sendResponse(payload, sessionKey)
    return


def sendResponse(data, key):

    """ Encrypt Data with Session Key"""
    encryptedData = Utilities.payload_encryptor_Fernet(data, key)
    encryptedData = encryptedData.decode('utf-8')
    """ Return Response """
    return JsonResponse({"data": encryptedData}, status=200)
