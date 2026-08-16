"""HTTP client for the pdf_generation microservice.

The gateway never renders PDFs itself — it forwards the scan result JSON to
the pdf_generation service and streams back the generated document.
"""

from __future__ import annotations

import os

import requests

PDF_GENERATION_URL = os.environ.get(
    "PDF_GENERATION_URL", "http://localhost:8000"
)


def generate_pdf(result: dict) -> bytes:
    """POST a scan result to pdf_generation and return the PDF bytes."""
    resp = requests.post(
        f"{PDF_GENERATION_URL}/generate", json=result, timeout=60
    )
    resp.raise_for_status()
    return resp.content