# update_server/stats/views.py
from __future__ import annotations
import json, time
from typing import Iterator
from flask import Blueprint, jsonify, request, Response, stream_with_context, current_app
from .collector import store

stats_api_bp = Blueprint("stats_api", __name__, url_prefix="/api/stats")

@stats_api_bp.get("/live")
def live():
    s = store.latest()
    # Αν δεν υπάρχει δείγμα ή είναι μπαγιάτικο, πάρε ένα τώρα.
    if not s or (time.time() - s.ts) > 1.5:
        host = current_app.config.get("STATS_TARGET_HOST", "1.1.1.1")
        port = int(current_app.config.get("STATS_TARGET_PORT", 53))
        s = store.sample_once(host, port)
    return jsonify(s.to_dict()), 200

@stats_api_bp.get("/range")
def range_():
    seconds = max(1, min(int(request.args.get("seconds", 300)), 3600))
    return jsonify(store.window(seconds)), 200

@stats_api_bp.get("/stream")
def stream():
    def gen() -> Iterator[bytes]:
        # στείλε πρώτο στιγμιότυπο αμέσως
        first = store.latest() or store.sample_once(
            current_app.config.get("STATS_TARGET_HOST", "1.1.1.1"),
            int(current_app.config.get("STATS_TARGET_PORT", 53)),
        )
        yield f"data: {json.dumps(first.to_dict())}\n\n".encode("utf-8")
        # μετά κάθε ~1s
        while True:
            time.sleep(1.0)
            s = store.latest()
            if not s or (time.time() - s.ts) > 1.5:
                s = store.sample_once(
                    current_app.config.get("STATS_TARGET_HOST", "1.1.1.1"),
                    int(current_app.config.get("STATS_TARGET_PORT", 53)),
                )
            yield f"data: {json.dumps(s.to_dict())}\n\n".encode("utf-8")
    headers = {"Content-Type":"text/event-stream","Cache-Control":"no-cache","Connection":"keep-alive"}
    return Response(stream_with_context(gen()), headers=headers)
