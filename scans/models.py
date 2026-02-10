from django.db import models

class Scan(models.Model):
    class Mode(models.TextChoices):
        PASSIVE = "PASSIVE", "Passive"
        AUTHORIZED = "AUTHORIZED", "Authorized"

    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        RUNNING = "RUNNING", "Running"
        DONE = "DONE", "Done"
        FAILED = "FAILED", "Failed"

    target_url = models.URLField()
    normalized_url = models.URLField(blank=True)
    mode = models.CharField(max_length=20, choices=Mode.choices, default=Mode.PASSIVE)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    progress = models.PositiveSmallIntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    error_message = models.TextField(blank=True)

    # optional white-box input
    dependency_file_name = models.CharField(max_length=255, blank=True)
    dependency_file_text = models.TextField(blank=True)

    def __str__(self):
        return f"Scan#{self.id} {self.target_url} [{self.status}]"


class Component(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="components")
    name = models.CharField(max_length=120)
    version = models.CharField(max_length=64, blank=True)
    confidence = models.PositiveSmallIntegerField(default=50)

    def __str__(self):
        return f"{self.name} {self.version} ({self.confidence}%)"


class Finding(models.Model):
    class Severity(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="findings")
    category = models.CharField(max_length=64)  # Headers/Cookies/TLS/CORS/InfoLeak/CVE
    severity = models.CharField(max_length=10, choices=Severity.choices, default=Severity.LOW)
    title = models.CharField(max_length=180)
    description = models.TextField()
    recommendation = models.TextField(blank=True)
    evidence = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return f"{self.severity} {self.title}"


class CVEItem(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="cves")
    component = models.ForeignKey(Component, on_delete=models.SET_NULL, null=True, blank=True)
    cve_id = models.CharField(max_length=32)
    cvss = models.CharField(max_length=16, blank=True)
    summary = models.TextField(blank=True)
    fixed_in = models.CharField(max_length=64, blank=True)
    references = models.JSONField(default=list, blank=True)

    def __str__(self):
        return self.cve_id
