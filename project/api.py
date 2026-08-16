"""REST API blueprint.

Exposes the asynchronous scan pipeline to the SPA-style scanner UI:
  POST /api/scans            -> enqueue a scan, return scan_id
  GET  /api/scans/<id>       -> poll status + result
  GET  /api/scans/<id>/report-> downloadable HTML/JSON report

Rate-limited per-user with Redis. Authentication required.
"""

from __future__ import annotations

import os
import sys

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


@api.route("/scans/<scan_id>", methods=["GET"])
@login_required
def get_scan(scan_id: str):
    cached = redis_client.get_scan_status(scan_id)
    if cached:
        return jsonify(cached), 200
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found."}), 404
    if scan.user_id != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Forbidden."}), 403
    return jsonify(scan.to_dict()), 200


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

    html = to_html(scan.result_json or {})
    return Response(html, mimetype="text/html")
