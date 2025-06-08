from datetime import datetime
import hashlib, json, os

from fastapi import FastAPI, Request, Response
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from jwcrypto import jwk, jws
from presidio_analyzer import AnalyzerEngine
from functools import lru_cache
import boto3
LOG_GROUP  = os.getenv("AUDIT_LOG_GROUP")
LOG_STREAM = os.getenv("AUDIT_LOG_STREAM", "primary")
logs = boto3.client("logs") if LOG_GROUP else None
@lru_cache
def get_analyzer():
    from presidio_analyzer import AnalyzerEngine
    nlp = SpacyNlpEngine()
    nlp.load({"en": "en_core_web_sm"})
    return AnalyzerEngine(nlp_engine=nlp, supported_languages=["en"])
    audit = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "path": request.url.path,
        "method": request.method,
        "pii": pii,
        "sha256": signed,
    }
    if logs:
        logs.put_log_events(
            logGroupName = LOG_GROUP,
            logStreamName= LOG_STREAM,
            logEvents=[{
                "timestamp": int(datetime.utcnow().timestamp()*1000),
                "message": json.dumps(audit),
            }],
        )

    response: Response = await call_next(request)
    response.headers["X-Content-SHA256"] = signed
    return response
@app.get("/health", tags=["internal"])
def health() -> dict:
    return {"status": "ok"}
@app.get("/health")
def health():
    return {"status": "ok"}
