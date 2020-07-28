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
        print(actual_message)
        # name = actual_message["name"]
        # national_code = actual_message["national_code"]
        # timestamp = actual_message["timestamp"]
        # if national_code is None or name is None:
        #     payload = {'status': 'fail', 'message': 'نام یا کدملی به درستی ارسال نشده است.'}
        #     return sendResponse(payload, sessionKey)
        # if Utilities.check_payload_timestamp(timestamp) == False:
        #     payload = {'status': 'fail', 'message': 'مهلت درخواست ارسال شده منقضی شده است.'}
        #     return sendResponse(payload, sessionKey)
    except Exception as e:
        print("#Exception-1: {}".format(e))
        payload = {'status': 'fail', 'message': 'درخواست به درستی ارسال نشده است.'}
        return sendResponse(payload, sessionKey)
