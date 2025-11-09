from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from ratelimit.decorators import ratelimit

@csrf_exempt
@ratelimit(key='ip', rate='5/m', block=True)        # for anonymous
@ratelimit(key='user_or_ip', rate='10/m', block=True)  # for logged-in users
def login_view(request):
    if request.method == "POST":
        return JsonResponse({"message": "Login request accepted"})
    return JsonResponse({"error": "Use POST"}, status=405)
