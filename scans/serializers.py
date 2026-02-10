from rest_framework import serializers
from .models import Scan, Finding, Component, CVEItem

class ScanCreateSerializer(serializers.ModelSerializer):
    dependency_file = serializers.FileField(required=False, allow_null=True)

    class Meta:
        model = Scan
        fields = ["id", "target_url", "mode", "dependency_file"]

    def create(self, validated_data):
        dep_file = validated_data.pop("dependency_file", None)
        scan = Scan.objects.create(**validated_data)
        if dep_file:
            scan.dependency_file_name = dep_file.name
            scan.dependency_file_text = dep_file.read().decode("utf-8", errors="ignore")
            scan.save(update_fields=["dependency_file_name", "dependency_file_text"])
        return scan


class ScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = ["id", "target_url", "normalized_url", "mode", "status", "progress", "created_at", "started_at", "finished_at", "error_message"]


class FindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Finding
        fields = ["id", "category", "severity", "title", "description", "recommendation", "evidence"]


class ComponentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Component
        fields = ["id", "name", "version", "confidence"]


class CVEItemSerializer(serializers.ModelSerializer):
    component = ComponentSerializer(allow_null=True)

    class Meta:
        model = CVEItem
        fields = ["id", "cve_id", "cvss", "summary", "fixed_in", "references", "component"]


class ScanReportSerializer(serializers.ModelSerializer):
    findings = FindingSerializer(many=True)
    components = ComponentSerializer(many=True)
    cves = CVEItemSerializer(many=True)

    class Meta:
        model = Scan
        fields = ["id", "target_url", "normalized_url", "mode", "status", "progress", "findings", "components", "cves"]
