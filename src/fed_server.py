from fastapi import FastAPI, Request
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from datetime import datetime
from presidio_analyzer.nlp_engine import SpacyNlpEngine
import hashlib, json
from presidio_analyzer.nlp_engine import SpacyNlpEngine
import os, boto3
from presidio_analyzer.nlp_engine import SpacyNlpEngine
LOG_GROUP = os.getenv('AUDIT_LOG_GROUP')
from presidio_analyzer.nlp_engine import SpacyNlpEngine
LOG_STREAM = os.getenv('AUDIT_LOG_STREAM', 'primary')
from presidio_analyzer.nlp_engine import SpacyNlpEngine
logs = boto3.client('logs') if LOG_GROUP else None
from presidio_analyzer.nlp_engine import SpacyNlpEngine

from presidio_analyzer.nlp_engine import SpacyNlpEngine
from jwcrypto import jwk, jws
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from presidio_analyzer import AnalyzerEngine
from functools import lru_cache



@lru_cache

def get_analyzer():

    from presidio_analyzer import AnalyzerEngine

    from presidio_analyzer.nlp_engine import SpacyNlpEngine

    model_cfg={"en": {"model_name": "en_core_web_sm"}}
    nlp_engine = SpacyNlpEngine(model_cfg)

    return AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
from presidio_analyzer.nlp_engine import SpacyNlpEngine
    model_cfg={"en": {"model_name": "en_core_web_sm"}}
    nlp_engine = SpacyNlpEngine(model_cfg)
APP = FastAPI(title="MCP-Fed Reference")
    model_cfg={"en": {"model_name": "en_core_web_sm"}}
    nlp_engine = SpacyNlpEngine(model_cfg)
    model_cfg={"en": {"model_name": "en_core_web_sm"}}
    nlp_engine = SpacyNlpEngine(model_cfg)
_KEY = jwk.JWK.generate(kty='EC', crv='P-256')

def _sign(p):
    token = jws.JWS(json.dumps(p).encode())
    token.add_signature(_KEY, None, json.dumps({"alg":"ES256"}))
    return token.serialize()

@APP.middleware("http")
async def audit_mw(req: Request, call_next):
    body = await req.body()
    pii = bool(get_analyzer().analyze(body.decode(), language='en'))
    resp = await call_next(req)
    audit = {"ts": datetime.utcnow().isoformat(),
             "path": req.url.path,
             "hash": hashlib.sha256(body).hexdigest(),
             "pii": pii,
             "sig": _sign({})}
    print(json.dumps(audit))
    if logs:
        logs.put_log_events(logGroupName=LOG_GROUP,
                            logStreamName=LOG_STREAM,
                            logEvents=[{"timestamp": int(datetime.utcnow().timestamp()*1000),
                                         "message": json.dumps(audit)}])
    return resp
