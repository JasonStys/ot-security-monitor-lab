"""Jason Stys: temporary loopback-only inert synthetic HTML preview for visual QA, not a hosted OT service."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 26
# variable: parser — line 28
# variable: args — line 30
# variable: document — line 31
# definition: ReportHandler — line 33
# definition: do_GET — line 36
# parameter: self — line 36
# definition: log_message — line 51
# parameter: args — line 51
# parameter: format — line 51
# parameter: self — line 51
# variable: server — line 54
# END CODE MAP

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from otmon.contracts import read_file


def main() -> None:
    """Serve one explicit bounded report at an ephemeral loopback port; no filesystem browsing or uploads."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    document = read_file(args.report, 65536)

    class ReportHandler(BaseHTTPRequestHandler):
        """Read-only single-file preview, with no request-derived local paths."""

        def do_GET(self) -> None:
            """Return only the known root report and defensive no-cache/referrer/embed headers."""
            if self.path != "/":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(document)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(document)

        def log_message(self, format: str, *args: object) -> None:
            """Suppress request path logs during synthetic preview; this is not a monitoring service."""

    with HTTPServer(("127.0.0.1", 0), ReportHandler) as server:
        print(
            json.dumps(
                dict(
                    author="Jason Stys",
                    preview_url=f"http://127.0.0.1:{server.server_port}/",
                    pid=os.getpid(),
                )
            ),
            flush=True,
        )
        server.serve_forever()


if __name__ == "__main__":
    main()
