"""Combined search and archive export HTTP endpoints."""

from __future__ import annotations

import io
import json
import zipfile

from flask.testing import FlaskClient


def run_cycle(client: FlaskClient, coil: str = "C-1") -> None:
    client.post(
        f"/api/cycle?coil={coil}&target=90&level=4.5&voltage=24"
        "&current=300&speed=1.4"
    )


def test_search_combines_window_and_categories(client: FlaskClient) -> None:
    run_cycle(client)
    response = client.get("/api/audit/search?kind=arc&kind=stop")
    body = response.get_json()
    assert response.status_code == 200
    assert body["ok"] is True
    assert body["count"] == len(body["events"])
    assert {event["kind"] for event in body["events"]} <= {"arc", "stop"}
    assert body["filter"]["kinds"] == ["arc", "stop"]
    stamps = [event["at"] for event in body["events"]]
    assert stamps == sorted(stamps)


def test_search_bad_timestamp_is_bad_request(client: FlaskClient) -> None:
    response = client.get("/api/audit/search?start=not-a-time")
    assert response.status_code == 400
    assert response.get_json()["ok"] is False


def test_search_unknown_kind_is_bad_request(client: FlaskClient) -> None:
    response = client.get("/api/audit/search?kind=banana")
    assert response.status_code == 400


def test_search_window_in_the_future_is_empty(client: FlaskClient) -> None:
    run_cycle(client)
    body = client.get(
        "/api/audit/search?start=2099-01-01T00:00:00Z"
    ).get_json()
    assert body["count"] == 0
    assert body["events"] == []


def test_export_returns_zip_and_lists_archive(client: FlaskClient) -> None:
    run_cycle(client)
    response = client.get("/api/audit/export?kind=arc")
    assert response.status_code == 201
    assert response.mimetype == "application/zip"
    name = response.headers["X-Archive-Name"]
    assert name.endswith(".zip")

    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        manifest = json.loads(archive.read("MANIFEST.json"))
        assert manifest["count"] >= 1
        assert manifest["filter"]["kinds"] == ["arc"]
        kinds = {item["kind"] for item in json.loads(archive.read("events.json"))}
    assert kinds == {"arc"}

    listing = client.get("/api/audit/archives").get_json()
    assert any(entry["archive"] == name for entry in listing["archives"])
    assert listing["ledger"]["ok"] is True

    download = client.get(f"/api/audit/download?name={name}")
    assert download.status_code == 200
    assert download.data == response.data


def test_export_empty_window_conflicts(client: FlaskClient) -> None:
    response = client.get("/api/audit/export?start=2099-01-01T00:00:00Z")
    assert response.status_code == 409
    assert response.get_json()["ok"] is False


def test_verify_reports_tampering_and_missing(client: FlaskClient, tmp_path) -> None:
    run_cycle(client)
    name = client.get("/api/audit/export?kind=stop").headers["X-Archive-Name"]
    result = client.get(f"/api/audit/verify?name={name}").get_json()
    assert result["verification"]["ok"] is True
    assert result["verification"]["readonly"] is True

    assert client.get("/api/audit/verify?name=missing.zip").status_code == 404
    assert client.get("/api/audit/download?name=missing.zip").status_code == 404


def test_ledger_endpoint(client: FlaskClient) -> None:
    run_cycle(client)
    client.get("/api/audit/export?kind=stop")
    ledger = client.get("/api/audit/ledger").get_json()["ledger"]
    assert ledger["ok"] is True
    assert ledger["count"] == 1
