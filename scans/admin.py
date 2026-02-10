from django.contrib import admin
from .models import Scan, Finding, Component, CVEItem

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("id", "target_url", "mode", "status", "progress", "created_at")
    search_fields = ("target_url",)
    list_filter = ("mode", "status")

admin.site.register(Finding)
admin.site.register(Component)
admin.site.register(CVEItem)
