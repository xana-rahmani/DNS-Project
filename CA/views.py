import os
from django.http.response import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from .models import User, Certificaat
from base import Utilities
from Voting_System import settings


# Create your views here.
def load_key(path):
    path = os.path.join('CA', path)
    path = os.path.join(settings.BASE_DIR, path)
    with open(path, 'r') as f:
        key = f.read()
    return key


@csrf_exempt
@require_http_methods(["GET", "POST"])
def generate_certificaat(request):
    try:
        actual_message = Utilities.decrypt(request.POST["request"],load_key('CA-private.key'))
        name = actual_message["name"]
        national_code = actual_message["national_code"]
    except:
        payload = {'status': 'fail', 'message': 'نام یا کدملی به درستی ارسال نشده است.'}
        encrypted_payload = Utilities.payload_encryptor(payload,load_key('CA-public.key'))
        return JsonResponse({'response': encrypted_payload}, status=200)

    try:
        # print('load_key', load_key('CA-private.key'))
        user = User.objects.filter(name=name, national_code=national_code)[0]
        if user:
            certificaat = Certificaat.objects.filter(user=user)[0]
            if certificaat:
                private_key = certificaat.private_key
                public_key = certificaat.public_key
                payload = {
                        'status': 'successful',
                        'message': 'گواهی شما.',
                        'private_key': private_key,

                    }
                encrypted_payload = Utilities.payload_encryptor(payload, load_key('CA-public.key'))
                return JsonResponse(
                    {
                        'response': encrypted_payload,
                    },
                    status=200)
            else:
                private_key, public_key = Utilities.generate_key()
                certificate = Certificaat(user=user, private_key=private_key, public_key=public_key)
                certificate.save()
                payload = {
                    'status': 'successful',
                    'message': 'گواهی با موفقیت ایجاد شد.',
                    'public_key': public_key

                }
                encrypted_payload = Utilities.payload_encryptor(payload, load_key('CA-public.key'))
                return JsonResponse(
                    {
                        'response': encrypted_payload,
                    },
                    status=200)
        else:
            encrypted_payload = Utilities.payload_encryptor({'status': 'fail', 'message': 'نام و کدملی شما معتبر نیست.'}, load_key('CA-public.key'))
            return JsonResponse(
                {
                    'response': encrypted_payload,
                },
                status=200)
    except:
        encrypted_payload = Utilities.payload_encryptor({'status': 'fail', 'message': 'لطفا بعدا تلاش کنید.'},
                                                        load_key('CA-public.key'))
        return JsonResponse(
            {
                'response': encrypted_payload,
            },
            status=200)

