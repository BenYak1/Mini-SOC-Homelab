from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging
from pathlib import Path

LOG_PATH = Path("/var/log/splunk_forwarded.log")
LISTEN_PORT = 8080


class SplunkWebhookHandler(BaseHTTPRequestHandler):
    # suppress default access log lines; comment out to re-enable
    def log_message(self, *_):
        pass

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length)
            payload = json.loads(raw_body)

            msg = payload.get("result", {}).get("msg")
            if msg:
                LOG_PATH.parent.mkdir(parents=True, exist_ok=True)  # ensure /var/log exists
                with LOG_PATH.open("a", encoding="utf-8") as f:
                    f.write(f"{msg}\n")
                logging.info("Forwarded msg: %s", msg)
                status = 200
                body = b"OK\n"
            else:
                logging.warning("JSON received but no result.msg field")
                status = 400
                body = b'Missing "result.msg"\n'
        except json.JSONDecodeError:
            logging.exception("Body is not valid JSON")
            status = 400
            body = b"Invalid JSON\n"
        except Exception:
            logging.exception("Unhandled error")
            status = 500
            body = b"Server error\n"

        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    server = HTTPServer(("", LISTEN_PORT), SplunkWebhookHandler)
    print(f"[+] Listening on 0.0.0.0:{LISTEN_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down…" )
        server.shutdown()


if __name__ == "__main__":
    main()
