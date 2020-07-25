from django.http.response import JsonResponse


# Create your views here.
def generate_certificaat(request):
    print("request: ", request)
    return JsonResponse(
        {
            'status': 'successful',
            'message': 'گواهی با موفقیت ایجاد شد.',
            'p-key': 100000
        },
        status=200)

