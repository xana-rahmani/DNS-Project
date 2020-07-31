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
        """ Read Request Data """
        sessionKey = Utilities.payload_decryptor_RSA(request.POST["sessionKey"], load_RSA_key('VS-private.key')).encode()
        actual_message = Utilities.payload_decryptor_Fernet(request.POST["data"], sessionKey)

        """ Read Vote Certificate Data """
        vote_crt = json.loads(actual_message.get("vote_crt"))
        AS_sessionKey = Utilities.payload_decryptor_RSA(vote_crt.get('sessionKey'), load_RSA_key('VS-private.key'))
        vote_crt_data = base64.b64decode(vote_crt.get('data').encode('ascii'))
        vote_crt_data = Utilities.payload_decryptor_Fernet(vote_crt_data, AS_sessionKey.encode())
        vote_crt_status = vote_crt_data.get("status")
        vote_crt_sk_voter = vote_crt_data.get("sk_voter")
        vote_crt_user_public_key = vote_crt_data.get("public_key")
        vote_crt_AS_signature = vote_crt_data.get("AS_signature")

        """ Read Vote Data """
        vote_data = actual_message.get("data").encode()
        user_vote = Utilities.payload_decryptor_Fernet(vote_data, vote_crt_sk_voter.encode())

        """ Check AS Certification """
        print("-- Check AS Certification")
        if checkAsCertificationSignature(sk_voter=vote_crt_sk_voter, public_key=vote_crt_user_public_key, signature=vote_crt_AS_signature):
            print("Xana 74938248")
        """ Check Vote """
        if vote_crt_status != "successful":
            payload = {'status': 'fail', 'message': 'مشکلی در حالت توکن ارسالی وجود دارد.'}
            return sendResponse(payload, sessionKey)
        if not checkVoteSignature(user_vote=user_vote, pubkey=vote_crt_user_public_key):
            payload = {'status': 'fail', 'message': 'امضای رای داده شده با کلید عمومی موجود در توکن مطابقت ندارد.'}
            return sendResponse(payload, sessionKey)
    except Exception as e:
        print("#Exception-1: {}".format(e))
        payload = {'status': 'fail', 'message': 'درخواست به درستی ارسال نشده است.'}
        # return sendResponse(payload, sessionKey)
    return


def checkVoteSignature(user_vote, pubkey):
    try:
        return Utilities.verify_vote(
                candidate_id=user_vote.get("vote"),
                pubkey=RSA.import_key(pubkey),
                signature=base64.b64decode(user_vote.get("signature").encode('ascii')))
    except Exception as e:
        return False


def checkAsCertificationSignature(sk_voter, public_key, signature):
    try:
        return Utilities.verify_AS_sign(
                    sk_voter=sk_voter,
                    public_key=public_key,
                    pubkey=settings.load_public_key('AS-public.key'),
                    signature=base64.b64decode(signature.encode('ascii'))
                )
    except Exception as e:
        return False


def sendResponse(data, key):

    """ Encrypt Data with Session Key"""
    encryptedData = Utilities.payload_encryptor_Fernet(data, key)
    encryptedData = encryptedData.decode('utf-8')
    """ Return Response """
    return JsonResponse({"data": encryptedData}, status=200)
