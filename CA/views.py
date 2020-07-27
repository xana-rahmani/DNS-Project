import os
from django.http.response import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from .models import User, Certificaat
from base import Utilities
from Voting_System import settings
from Crypto.PublicKey import RSA


# Create your views here.
def load_RSA_key(path):
    path = os.path.join('CA', path)
    path = os.path.join(settings.BASE_DIR, path)
    with open(path, 'r') as f:
        key_data = f.read()
    key = RSA.import_key(key_data)
    return key


@csrf_exempt
@require_http_methods(["POST"])
def generate_certificaat(request):
    try:
        sessionKey = Utilities.payload_decryptor_RSA(request.POST["sessionKey"], load_RSA_key('CA-private.key')).encode()
        actual_message = Utilities.payload_decryptor_Fernet(request.POST["data"], sessionKey)
        name = actual_message["name"]
        national_code = actual_message["national_code"]
        if national_code is None or name is None:
            payload = {'status': 'fail', 'message': 'نام یا کدملی به درستی ارسال نشده است.'}
            return sendResponse(payload, sessionKey)
    except Exception as e:
        print("#Exception-1: {}".format(e))
        payload = {'status': 'fail', 'message': 'درخواست به درستی ارسال نشده است.'}
        return sendResponse(payload, sessionKey)

    try:
        userObjects = User.objects.filter(name=name, national_code=national_code)
        if userObjects.count() <= 0:
            payload = {'status': 'fail', 'message': 'نام یا کدملی شما معتبر نیست.'}
            return sendResponse(payload, sessionKey)
        elif userObjects.count() > 1:
            print("#ERROR IN SYSTEM: 2 user with same national code")
            payload = {'status': 'fail', 'message': 'لطفا با پشتیبانی تماس بگیرید.'}
            return sendResponse(payload, sessionKey)

        user = userObjects.first()
        if user:
            payload = create_certificaat(user)
            return sendResponse(payload, sessionKey)
        else:
            payload = {'status': 'fail', 'message': 'کاربر یافت نشد، لطفا دوباره تلاش کنید.'}
            return sendResponse(payload, sessionKey)
    except Exception as e:
        print("#Exception2: {}".format(e))
        payload = {'status': 'fail', 'message': 'لطفا با پشتیبانی تماس بگیرید.'}
        return sendResponse(payload, sessionKey)


def create_certificaat(user):
    certificaat = Certificaat.objects.filter(user=user)
    if certificaat.count() == 1:
        certificaat = certificaat.first()
        private_key = certificaat.private_key
        public_key = certificaat.public_key
        payload = {
            'status': 'successful',
            'message': 'گواهی شما ارسال شد.',
            'private_key': private_key,
            'public_key': public_key

        }
        return payload
    else:
        private_key, public_key = Utilities.generate_RSA_key()
        certificate = Certificaat(user=user, private_key=private_key, public_key=public_key)
        certificate.save()
        payload = {
            'status': 'successful',
            'message': 'گواهی با موفقیت ایجاد شد.',
            'private_key': private_key,
            'public_key': public_key

        }
        return payload


def sendResponse(data, key):

    """ Encrypt Data with Session Key"""
    encryptedData = Utilities.payload_encryptor_Fernet(data, key)
    encryptedData = encryptedData.decode('utf-8')
    """ Return Response """
    return JsonResponse({"data": encryptedData}, status=200)
