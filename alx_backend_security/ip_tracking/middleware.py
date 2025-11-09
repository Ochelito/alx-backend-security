import requests
from django.core.cache import cache
from .models import RequestLog
from django.utils import timezone
from .models import BlockedIP


class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = request.META.get('HTTP_X_FORWARDED_FOR')
        if ip:
            ip = ip.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')

        # Check cache for geolocation data
        cache_key = f"geo_{ip}"
        geo_data = cache.get(cache_key)

        if not geo_data:
            try:
                response = requests.get(f"https://ipapi.co/{ip}/json/")
                data = response.json()
                geo_data = {
                    "country": data.get("country_name", "Unknown"),
                    "city": data.get("city", "Unknown"),
                }
                cache.set(cache_key, geo_data, timeout=86400)  # 24 hours
            except Exception:
                geo_data = {"country": "Unknown", "city": "Unknown"}

        # Log request
        RequestLog.objects.create(
            ip_address=ip,
            path=request.path,
            timestamp=timezone.now(),
            country=geo_data["country"],
            city=geo_data["city"],
        )

        return self.get_response(request)

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
