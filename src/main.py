from .fed_server import APP as app
@app.get("/")
def root(): return {"hello": "mcp-fed"}
