from fastapi import FastAPI, Request
from datetime import datetime
import hashlib, json
from jwcrypto import jwk, jws
from presidio_analyzer import AnalyzerEngine
APP = FastAPI(title="MCP-Fed Reference")
analyzer = AnalyzerEngine()
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
    return resp
