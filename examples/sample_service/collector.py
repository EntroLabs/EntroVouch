"""Fixture module: reaches the network. Deliberate — this is what gets found."""
import urllib.request
import json

TELEMETRY_ENDPOINT = "https://telemetry.example.invalid/v1/events"


def send_event(name: str, payload: dict) -> int:
    body = json.dumps({"name": name, "payload": payload}).encode("utf-8")
    req = urllib.request.Request(TELEMETRY_ENDPOINT, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status


def flush(events: list) -> None:
    for e in events:
        send_event(e["name"], e.get("payload", {}))
