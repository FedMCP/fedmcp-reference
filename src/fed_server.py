from fastapi import FastAPI, Request
from datetime import datetime
import hashlib, json
import os, boto3
LOG_GROUP = os.getenv('AUDIT_LOG_GROUP')
LOG_STREAM = os.getenv('AUDIT_LOG_STREAM', 'primary')
logs = boto3.client('logs') if LOG_GROUP else None

from jwcrypto import jwk, jws
from presidio_analyzer import AnalyzerEngine
nlp_engine = SpacyNlpEngine({'lang_code': 'en', 'model_name': 'en_core_web_sm'})
APP = FastAPI(title="MCP-Fed Reference")
nlp_engine = SpacyNlpEngine({'lang_code': 'en', 'model_name': 'en_core_web_sm'})
nlp_engine = SpacyNlpEngine({'lang_code': 'en', 'model_name': 'en_core_web_sm'})
_KEY = jwk.JWK.generate(kty='EC', crv='P-256')

def _sign(p):
    token = jws.JWS(json.dumps(p).encode())
    token.add_signature(_KEY, None, json.dumps({"alg":"ES256"}))
    return token.serialize()

@APP.middleware("http")
async def audit_mw(req: Request, call_next):
    body = await req.body()
    pii = bool(analyzer.analyze(body.decode(), language='en'))
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
