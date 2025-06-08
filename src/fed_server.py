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



