import os
import json
import base64
import logging
from django.http.response import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from .models import Candidates, Votes
from base import Utilities
from Voting_System import settings
from Crypto.PublicKey import RSA
from django.db import IntegrityError, transaction


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
        logging.info("\n\n\t\t---- VS: vote receive a request -----\n")
        """ Read Request Data """
        sessionKey = Utilities.payload_decryptor_RSA(request.POST["sessionKey"], load_RSA_key('VS-private.key')).encode()
        actual_message = Utilities.payload_decryptor_Fernet(request.POST["data"], sessionKey)
        logging.info("VS request actual message: {}".format(actual_message))

        """ Read Vote Certificate Data """
        vote_crt = json.loads(actual_message.get("vote_crt"))
        logging.info("VS request vote_crt : {}".format(vote_crt))
        AS_sessionKey = Utilities.payload_decryptor_RSA(vote_crt.get('sessionKey'), load_RSA_key('VS-private.key'))
        vote_crt_data = base64.b64decode(vote_crt.get('data').encode('ascii'))
        vote_crt_data = Utilities.payload_decryptor_Fernet(vote_crt_data, AS_sessionKey.encode())
        vote_crt_status = vote_crt_data.get("status")
        vote_crt_sk_voter = vote_crt_data.get("sk_voter")
        vote_crt_user_public_key = vote_crt_data.get("public_key")
        vote_crt_AS_signature = vote_crt_data.get("AS_signature")
        logging.info("SK Voter : {}".format(vote_crt_sk_voter))
        logging.info("User Public Key : {}".format(vote_crt_user_public_key))
        logging.info("AS Signature : {}".format(vote_crt_AS_signature))

        """ Read Vote Data """
        vote_data = actual_message.get("data").encode()
        user_vote = Utilities.payload_decryptor_Fernet(vote_data, vote_crt_sk_voter.encode())
        logging.info("User Vote : {}".format(user_vote))
    except Exception as e:
        print("#Exception-1: {}".format(e))
        logging.info("#Exception-1: {}".format(e))
        payload = {'status': 'fail', 'message': 'درخواست به درستی ارسال نشده است.'}
        return sendResponse(payload, sessionKey)

    try:
        """ Check AS Certification """
        if not checkAsCertificationSignature(sk_voter=vote_crt_sk_voter, public_key=vote_crt_user_public_key,
                                         signature=vote_crt_AS_signature):
            message = 'امضای گواهی AS معتبر نمی‌باشد.'
            logging.info(message)
            payload = {'status': 'fail', 'message': message}
            return sendResponse(payload, sessionKey)

        """ Check Vote """
        if vote_crt_status != "successful":
            message = 'مشکلی در حالت توکن ارسالی وجود دارد.'
            logging.info(message)
            payload = {'status': 'fail', 'message': message}
            return sendResponse(payload, sessionKey)
        if not checkVoteSignature(user_vote=user_vote, pubkey=vote_crt_user_public_key):
            message = "امضای رای داده شده با کلید عمومی موجود در توکن مطابقت ندارد."
            logging.info(message)
            payload = {'status': 'fail', 'message': message}
            return sendResponse(payload, sessionKey)
        payload = addVote(candidate_id=user_vote.get("vote"), public_key=vote_crt_user_public_key)
        return sendResponse(payload, sessionKey)
    except Exception as e:
        print("#Exception-2: {}".format(e))
        logging.info("#Exception-2: {}".format(e))
        payload = {'status': 'fail', 'message': 'درخواست به درستی ارسال نشده است.'}
        return sendResponse(payload, sessionKey)


@require_http_methods(["GET"])
def seeVote(request):
    logging.info("\n\n\t\t---- VS: see vote receive a request -----\n")
    candidates = Candidates.objects.all()
    numerOfVote = {}
    for candidate in candidates:
        numerOfVote[candidate.candidate_id] = candidate.number_of_votes
    return JsonResponse(numerOfVote, status=200)


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


def addVote(candidate_id, public_key):

    """ Find  candidate """
    candidate = Candidates.objects.filter(candidate_id=candidate_id)
    if candidate.count() <= 0:
        message = 'کاندیدای با این آیدی وجود ندارد.'
        logging.info(message)
        return {'status': 'fail', 'message': message}
    elif candidate.count() == 1:
        candidate = candidate.first()  # Candidate Found
    else:
        print("#ERROR IN SYSTEM: 2 candidate with same candidate_id")
        logging.info("#ERROR IN SYSTEM: 2 candidate with same candidate_id")
        return {'status': 'fail', 'message': 'لطفا با پشتیبانی تماس بگیرید.'}

    """ Add Vote for Candidate """
    try:
        user_vote = Votes.objects.filter(public_key=public_key)
        if user_vote.count() != 0:
            user_vote = user_vote.first()
            voted_to = user_vote.voted_to
            message = 'شما قبلا به کاندید {} رای داده اید.'.format(voted_to.candidate_id)
            logging.info(message)
            return {'status': 'successful', 'message': message}
        elif user_vote.count() == 0:
            with transaction.atomic():
                newVote = Votes(public_key=public_key, voted_to=candidate)
                newVote.save()
                temp_number_of_vote = candidate.number_of_votes
                candidate.number_of_votes = temp_number_of_vote + 1
                candidate.save(update_fields=['number_of_votes'])
                message = 'رای شما به کاندیدا با شماره {} ثبت گردید.'.format(candidate.candidate_id)
                logging.info(message)
                return {'status': 'successful', 'message': message}
    except IntegrityError:
        print("#ERROR IN SYSTEM: error in add Vote in Data Base")
        logging.info("#ERROR IN SYSTEM: error in add Vote in Data Base")
        return {'status': 'fail', 'message': 'لطفا با پشتیبانی تماس بگیرید.'}
    logging.info('لطفا با پشتیبانی تماس بگیرید.')
    return {'status': 'fail', 'message': 'لطفا با پشتیبانی تماس بگیرید.'}


def sendResponse(data, key):

    """ Encrypt Data with Session Key"""
    encryptedData = Utilities.payload_encryptor_Fernet(data, key)
    encryptedData = encryptedData.decode('utf-8')
    """ Return Response """
    return JsonResponse({"data": encryptedData}, status=200)
