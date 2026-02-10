from django.shortcuts import render

# Create your views here.
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status as http_status

from .models import Scan
from .serializers import ScanCreateSerializer, ScanSerializer, ScanReportSerializer
from .tasks import run_scan_task

class ScanViewSet(viewsets.ModelViewSet):
    queryset = Scan.objects.all().order_by("-id")

    def get_serializer_class(self):
        if self.action == "create":
            return ScanCreateSerializer
        return ScanSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        scan = serializer.save()

        # Background task (Celery). If celery/redis not running, user can still call /run-sync/ action.
        try:
            run_scan_task.delay(scan.id)
        except Exception:
            pass

        return Response({"id": scan.id, "status": scan.status}, status=http_status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"])
    def run_sync(self, request, pk=None):
        """Agar Celery ishlamasa, sync ishlatish uchun."""
        scan = self.get_object()
        run_scan_task(scan.id)
        scan.refresh_from_db()
        return Response(ScanSerializer(scan).data)

    @action(detail=True, methods=["get"])
    def report(self, request, pk=None):
        scan = self.get_object()
        data = ScanReportSerializer(scan).data
        return Response(data)
