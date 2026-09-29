"""Combined audit search, export and verification endpoints."""

from __future__ import annotations

import io
import json
import zipfile

from flask.testing import FlaskClient


def _run_cycle(client: FlaskClient) -> None:
    client.post(
        "/api/cycle?coil=C-9&target=90&level=4.5&voltage=24&current=300&speed=1.4"
    )


def test_audit_accepts_multiple_kinds(client: FlaskClient) -> None:
    _run_cycle(client)
    response = client.get("/api/audit?kind=arc&kind=stop&limit=100")
    assert response.status_code == 200
    body = response.get_json()
    assert body["events"]
    assert {event["kind"] for event in body["events"]} <= {"arc", "stop"}
    assert set(body["filter"]["kinds"]) == {"arc", "stop"}
    assert body["count"] == len(body["events"])


def test_audit_filters_by_time_window(client: FlaskClient) -> None:
    _run_cycle(client)
    far_future = client.get(
        "/api/audit?start=2099-01-01T00:00:00Z"
    ).get_json()
    assert far_future["count"] == 0
    spanned = client.get(
        "/api/audit?start=2000-01-01T00:00:00Z&end=2100-01-01T00:00:00Z&limit=-1"
    ).get_json()
    assert spanned["count"] >= 5


def test_audit_rejects_bad_parameters(client: FlaskClient) -> None:
    assert client.get("/api/audit?kind=bogus").status_code == 400
    assert client.get("/api/audit?start=monday").status_code == 400
    inverted = client.get(
        "/api/audit?start=2099-01-01T00:00:00Z&end=2000-01-01T00:00:00Z"
    )
    assert inverted.status_code == 400


def test_export_downloads_a_verifiable_archive(client: FlaskClient) -> None:
    _run_cycle(client)
    response = client.get("/api/audit/export?kind=arc&kind=stop")
    assert response.status_code == 200
    assert response.mimetype == "application/zip"
    blob = response.data
    assert zipfile.is_zipfile(io.BytesIO(blob))
    assert response.headers["X-Archive-Count"] == "2" or int(
        response.headers["X-Archive-Count"]
    ) >= 2

    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        events = json.loads(zf.read("events.json"))
        manifest = json.loads(zf.read("manifest.json"))
    assert {event["kind"] for event in events} <= {"arc", "stop"}
    assert manifest["criteria"]["kinds"] == ["arc", "stop"]

    verify = client.post(
        "/api/audit/verify",
        data={"archive": (io.BytesIO(blob), "range.zip")},
        content_type="multipart/form-data",
    )
    assert verify.status_code == 200
    assert verify.get_json()["ok"] is True

    ledger = client.get("/api/audit/exports").get_json()["exports"]
    assert len(ledger) == 1
    assert ledger[0]["eventCount"] == manifest["eventCount"]


def _tamper(blob: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(blob)) as src, zipfile.ZipFile(buffer, "w") as dst:
        for member in src.infolist():
            if member.filename == "events.json":
                changed = json.loads(src.read(member))
                changed[0]["message"] = "altered after export"
                dst.writestr(member, json.dumps(changed))
            else:
                dst.writestr(member, src.read(member))
    return buffer.getvalue()


def test_tampered_archive_is_unprocessable(client: FlaskClient) -> None:
    _run_cycle(client)
    blob = client.get("/api/audit/export").data
    forged = _tamper(blob)
    response = client.post(
        "/api/audit/verify",
        data={"archive": (io.BytesIO(forged), "range.zip")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 422
    assert response.get_json()["ok"] is False


def test_verify_without_a_file_is_a_bad_request(client: FlaskClient) -> None:
    response = client.post("/api/audit/verify", data={}, content_type="multipart/form-data")
    assert response.status_code == 400
