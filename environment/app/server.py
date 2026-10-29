"""Synthetic trusted-gateway lab: identities are fixture labels, not credentials."""
import argparse
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from service import execute, APIError

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="/tmp/tenant-lab.sqlite")
    parser.add_argument("--fixture", default="/app/fixtures.json")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    db = sqlite3.connect(args.db)
    db.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
    if not db.execute("SELECT 1 FROM state WHERE id=1").fetchone():
        with open(args.fixture) as f:
            fixture = json.load(f)
        db.execute("INSERT INTO state VALUES(1, ?)", (json.dumps(fixture),))
        db.commit()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def respond(self, status, value):
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def do_GET(self):
            if self.path == "/health":
                self.respond(200, {"ok": True})
            else:
                self.respond(404, {"error": "unknown route"})
        def do_POST(self):
            if self.path != "/rpc":
                self.respond(404, {"error": "unknown route"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1048576:
                    raise APIError(400, "invalid body length")
                req = json.loads(self.rfile.read(length))
                actor = self.headers.get("X-Lab-Identity", "")
                if not actor:
                    raise APIError(401, "missing identity")
                db.execute("BEGIN IMMEDIATE")
                state = json.loads(db.execute("SELECT payload FROM state WHERE id=1").fetchone()[0])
                result = execute(state, actor, req["op"], req.get("data", {}))
                db.execute("UPDATE state SET payload=? WHERE id=1", (json.dumps(state),))
                db.commit()
                self.respond(200, {"result": result})
            except APIError as e:
                db.rollback()
                self.respond(e.status, {"error": e.message})
            except (ValueError, KeyError, TypeError):
                db.rollback()
                self.respond(400, {"error": "invalid request"})
            except Exception:
                db.rollback()
                self.respond(500, {"error": "internal error"})
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    print(json.dumps({"port": server.server_port}), flush=True)
    server.serve_forever()

if __name__ == "__main__":
    main()
