from .fed_server import app
@app.get("/")
def root(): return {"hello": "fedmcp"}
