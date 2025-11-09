from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from ip_tracking.models import RequestLog, SuspiciousIP

@shared_task
def detect_anomalies():
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)
    sensitive_paths = ['/admin', '/login']

    # Get recent logs
    recent_logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)

    # 1️⃣ Flag IPs with >100 requests/hour
    for ip, count in recent_logs.values_list('ip_address').annotate(total=models.Count('id')):
        if count > 100:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                defaults={'reason': f"High request volume: {count} in the past hour"}
            )

    # 2️⃣ Flag IPs accessing sensitive endpoints
    for log in recent_logs.filter(path__in=sensitive_paths):
        SuspiciousIP.objects.get_or_create(
            ip_address=log.ip_address,
            defaults={'reason': f"Accessed sensitive path: {log.path}"}
        )
