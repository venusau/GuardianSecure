"""REST API blueprint.

Exposes the asynchronous scan pipeline to the SPA-style scanner UI:
  POST /api/scans            -> enqueue a scan, return scan_id
  GET  /api/scans/<id>       -> poll status + result
  GET  /api/scans/<id>/report-> downloadable HTML/JSON report

Rate-limited per-user with Redis. Authentication required.
"""

from __future__ import annotations

import csv
import io
import os
import sys
from datetime import datetime, timezone, timedelta

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from flask import Blueprint, request, jsonify, current_app, Response
from flask_login import login_required, current_user

from . import db
from .models import Scan
from .scan_service import submit_scan
from libs.redis_client import redis_client
from scanner.report import to_html

api = Blueprint("api", __name__, url_prefix="/api")

RATE_LIMIT = int(os.environ.get("API_RATE_LIMIT", "20"))
RATE_WINDOW = int(os.environ.get("API_RATE_WINDOW", "60"))


def _rate_limited() -> tuple[bool, int]:
    key = f"api:{current_user.id if current_user.is_authenticated else request.remote_addr}"
    return redis_client.rate_limit(key, RATE_LIMIT, RATE_WINDOW)


@api.route("/scans", methods=["POST"])
@login_required
def create_scan():
    allowed, remaining = _rate_limited()
    if not allowed:
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

    data = request.get_json(silent=True) or {}
    target = (data.get("targetURL") or "").strip()
    scan_type = data.get("options", "Passive Scan")
    if not target or not target.startswith(("http://", "https://")):
        return jsonify({"error": "A valid http(s) target URL is required."}), 400
    if scan_type not in ("Passive Scan", "Active Scan"):
        scan_type = "Passive Scan"

    app = current_app._get_current_object()
    scan_id = submit_scan(app, current_user.id, target, scan_type)
    return jsonify({"scan_id": scan_id, "status": "queued"}), 202


@api.route("/scans", methods=["GET"])
@login_required
def list_scans():
    """Paginated scan history. Admins see every user's scans, others only their own."""
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(50, max(1, request.args.get("per_page", 15, type=int)))
    q = Scan.query
    if current_user.role != "admin":
        q = q.filter(Scan.user_id == current_user.id)
    status = request.args.get("status")
    if status:
        q = q.filter(Scan.status == status)
    qtext = (request.args.get("q") or "").strip()
    if qtext:
        q = q.filter(Scan.target.ilike(f"%{qtext}%"))
    q = q.order_by(Scan.created_at.desc())
    total = q.count()
    rows = q.offset((page - 1) * per_page).limit(per_page).all()
    return jsonify({
        "scans": [s.to_summary_dict() for s in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
    })


@api.route("/scans/stats", methods=["GET"])
@login_required
def scan_stats():
    """Aggregate counters for the history dashboard."""
    q = Scan.query
    if current_user.role != "admin":
        q = q.filter(Scan.user_id == current_user.id)
    scans = q.all()
    now = datetime.now(timezone.utc)
    total = len(scans)
    completed = sum(1 for s in scans if s.status == "completed")
    high_critical = 0
    findings = 0
    durations = []
    for s in scans:
        r = s.result_json or {}
        summary = r.get("summary") or {}
        high_critical += int(summary.get("HIGH") or 0) + int(summary.get("CRITICAL") or 0)
        findings += len(r.get("findings") or [])
        if r.get("duration_seconds"):
            durations.append(float(r["duration_seconds"]))
    last_7_days = sum(1 for s in scans if s.created_at and (now - s.created_at).days < 7)
    return jsonify({
        "total": total,
        "completed": completed,
        "high_critical": high_critical,
        "findings": findings,
        "avg_duration_seconds": round(sum(durations) / len(durations), 2) if durations else None,
        "last_7_days": last_7_days,
    })


@api.route("/scans/<scan_id>", methods=["GET"])
@login_required
def get_scan(scan_id: str):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found."}), 404
    if scan.user_id != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Forbidden."}), 403
    # ownership verified against Postgres first; cache is only a fast status copy
    cached = redis_client.get_scan_status(scan_id)
    if cached:
        return jsonify(cached), 200
    return jsonify(scan.to_dict()), 200


@api.route("/scans/<scan_id>/rerun", methods=["POST"])
@login_required
def rerun_scan(scan_id: str):
    """Re-submit a previous scan against the same target and mode."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found."}), 404
    if scan.user_id != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Forbidden."}), 403
    app = current_app._get_current_object()
    new_id = submit_scan(app, scan.user_id, scan.target, scan.scan_type)
    return jsonify({"scan_id": new_id, "status": "queued", "target": scan.target}), 202


@api.route("/scans/<scan_id>", methods=["DELETE"])
@login_required
def delete_scan(scan_id: str):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found."}), 404
    if scan.user_id != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Forbidden."}), 403
    redis_client.invalidate(f"scan:{scan_id}")
    db.session.delete(scan)
    db.session.commit()
    return jsonify({"deleted": True}), 200


@api.route("/scans/<scan_id>/report", methods=["GET"])
@login_required
def get_report(scan_id: str):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found."}), 404
    if scan.user_id != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Forbidden."}), 403

    if request.args.get("format") == "json":
        return jsonify(scan.result_json or {}), 200

    if request.args.get("format") == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["severity", "owasp", "title", "url", "remediation", "cwe"])
        for f in (scan.result_json or {}).get("findings", []):
            writer.writerow([
                f.get("severity", ""), f.get("category", ""), f.get("title", ""),
                f.get("url", ""), f.get("remediation", ""), f.get("cwe", ""),
            ])
        return Response(
            buf.getvalue(), mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=scan-{scan_id[:8]}.csv"},
        )

    html = to_html(scan.result_json or {})
    return Response(html, mimetype="text/html")
