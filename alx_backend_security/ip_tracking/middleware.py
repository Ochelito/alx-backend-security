from .models import RequestLog
from django.utils import timezone
from django.http import HttpResponseForbidden
from .models import BlockedIP


class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = request.META.get('REMOTE_ADDR', '')
        path = request.path
        RequestLog.objects.create(ip_address=ip, path=path, timestamp=timezone.now())
        response = self.get_response(request)
        return response

class IPBlockMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Extract client IP address
        ip = request.META.get('HTTP_X_FORWARDED_FOR')
        if ip:
            ip = ip.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')

        # Check if IP is blocked
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("🚫 Access denied: Your IP is blocked.")

        # Continue with normal processing
        response = self.get_response(request)
        return response
