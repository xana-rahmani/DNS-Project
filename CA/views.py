from django.http.response import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from .models import User, Certificaat


# Create your views here.
@csrf_exempt
@require_http_methods(["GET", "POST"])
def generate_certificaat(request):
    try:
        name = request.POST["name"]
        national_code = request.POST["national_code"]
    except:
        return JsonResponse({'status': 'fail', 'message': 'نام یا کدملی به درستی ارسال نشده است.'}, status=200)

    try:
        user = User.objects.get(name=name, national_code=national_code)
        if user:
            certificaat = Certificaat.objects.filter(user=user)[0]
            private_key = certificaat.private_key
            public_key = certificaat.public_key
            return JsonResponse(
                {
                    'status': 'successful',
                    'message': 'گواهی شما.',
                    'public_key': public_key
                },
                status=200)
        else:
            user = User(name=name, national_code=national_code)
            user.save()
            private_key = "00"
            public_key = "11"
            Certificaat(user=user, private_key=private_key, public_key=public_key).save()
            return JsonResponse(
                {
                    'status': 'successful',
                    'message': 'گواهی با موفقیت ایجاد شد.',
                    'public_key': public_key
                },
                status=200)
    except:
        return JsonResponse({'status': 'fail', 'message': 'لطفا بعدا تلاش کنید.'}, status=200)
