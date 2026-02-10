from celery import shared_task
from django.utils import timezone
from .models import Scan, Finding, Component, CVEItem
from .scanner.engine import run_passive_scan

@shared_task(bind=True)
def run_scan_task(self, scan_id: int):
    scan = Scan.objects.get(id=scan_id)
    scan.status = Scan.Status.RUNNING
    scan.started_at = timezone.now()
    scan.progress = 5
    scan.save(update_fields=["status", "started_at", "progress"])

    try:
        report = run_passive_scan(
            scan.target_url,
            dep_file_name=scan.dependency_file_name,
            dep_text=scan.dependency_file_text
        )
        scan.normalized_url = report.get("final_url") or report.get("normalized_url") or scan.target_url
        scan.progress = 70
        scan.save(update_fields=["normalized_url", "progress"])

        # clear old
        scan.findings.all().delete()
        scan.components.all().delete()
        scan.cves.all().delete()

        # components
        comp_map = {}
        for c in report["components"]:
            comp = Component.objects.create(
                scan=scan,
                name=c.get("name", "")[:120],
                version=str(c.get("version", ""))[:64],
                confidence=int(c.get("confidence", 50)),
            )
            comp_map[(comp.name.lower(), comp.version)] = comp

        scan.progress = 85
        scan.save(update_fields=["progress"])

        # findings
        for f in report["findings"]:
            Finding.objects.create(
                scan=scan,
                category=f.get("category", "General")[:64],
                severity=f.get("severity", "LOW"),
                title=f.get("title", "")[:180],
                description=f.get("description", ""),
                recommendation=f.get("recommendation", ""),
                evidence=f.get("evidence", {}) or {},
            )

        # cves
        for c in report["cves"]:
            cname = (c.get("component_name") or "").lower()
            cver = str(c.get("version") or "")
            comp = None
            # best effort: find any matching component by name
            for (n, v), obj in comp_map.items():
                if n == cname:
                    comp = obj
                    break

            CVEItem.objects.create(
                scan=scan,
                component=comp,
                cve_id=c.get("cve_id", "")[:32],
                cvss=str(c.get("cvss", ""))[:16],
                summary=c.get("summary", ""),
                fixed_in=str(c.get("fixed_in", ""))[:64],
                references=c.get("references", []) or [],
            )

        scan.status = Scan.Status.DONE
        scan.progress = 100
        scan.finished_at = timezone.now()
        scan.save(update_fields=["status", "progress", "finished_at"])

        return {"status": "ok", "scan_id": scan_id}

    except Exception as e:
        scan.status = Scan.Status.FAILED
        scan.error_message = str(e)
        scan.finished_at = timezone.now()
        scan.progress = 100
        scan.save(update_fields=["status", "error_message", "finished_at", "progress"])
        raise
