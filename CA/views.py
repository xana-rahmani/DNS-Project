import os
from django.http.response import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from .models import User, Certificaat
from base import Utilities
from Voting_System import settings

# Create your views here.
@csrf_exempt
@require_http_methods(["GET", "POST"])
def generate_certificaat(request):
    try:
        name = request.POST["name"]
        national_code = request.POST["national_code"]
        if national_code is None or name is None:
            return JsonResponse({'status': 'fail', 'message': 'نام یا کدملی به درستی ارسال نشده است.'}, status=200)
    except:
        return JsonResponse({'status': 'fail', 'message': 'نام یا کدملی به درستی ارسال نشده است.'}, status=200)

    try:
        # print('load_key', load_key('CA-private.key'))
        user = User.objects.filter(name=name, national_code=national_code)
        if user.count() <= 0:
            return JsonResponse({'status': 'fail', 'message': 'نام و کدملی شما معتبر نیست.'}, status=200)
        elif user.count() > 1:
            print("#ERROR IN SYSTEM: 2 user with same national code")
            return JsonResponse({'status': 'fail', 'message': 'لطفا با پشتیبانی تماس بگیرید.'}, status=200)

        user = User.objects.filter(name=name, national_code=national_code).first()
        if user:
            certificaat = Certificaat.objects.filter(user=user)
            if certificaat.count() == 1:
                certificaat = certificaat.first()
                private_key = certificaat.private_key
                public_key = certificaat.public_key
                return JsonResponse(
                    {
                        'status': 'successful',
                        'message': 'گواهی شما ارسال شد.',
                        'private_key': private_key,
                        'public_key': public_key
                    },
                    status=200)
            else:
                private_key, public_key = Utilities.generate_key()
                certificate = Certificaat(user=user, private_key=private_key, public_key=public_key)
                certificate.save()
                return JsonResponse(
                    {
                        'status': 'successful',
                        'message': 'گواهی با موفقیت ایجاد شد.',
                        'public_key': public_key
                    },
                    status=200)
        else:
            return JsonResponse({'status': 'fail', 'message': 'لطفا بعدا تلاش کنید.'}, status=200)
    except Exception as e:
        print("#Exception: {}".format(e))
        return JsonResponse({'status': 'fail', 'message': 'لطفا بعدا تلاش کنید.'}, status=200)


def load_key(path):
    path = os.path.join('CA', path)
    path = os.path.join(settings.BASE_DIR, path)
    with open(path, 'r') as f:
        key = f.read()
    return key