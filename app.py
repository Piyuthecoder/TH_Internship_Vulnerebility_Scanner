"""
VulnProbe - Professional Vulnerability Scanner
Flask backend with real scanning capabilities
"""

import socket
import ssl
import json
import datetime
import threading
import time
import re
import urllib.request
import urllib.error
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from collections import defaultdict

app = Flask(__name__)

# ─────────────────────────────────────────────
#  PORT DEFINITIONS
# ─────────────────────────────────────────────
COMMON_PORTS = {
    21:   ("FTP",        "File Transfer – often unencrypted"),
    22:   ("SSH",        "Secure Shell"),
    23:   ("Telnet",     "Unencrypted remote shell – HIGH RISK"),
    25:   ("SMTP",       "Mail transfer"),
    53:   ("DNS",        "Domain Name System"),
    80:   ("HTTP",       "Unencrypted web traffic"),
    110:  ("POP3",       "Mail retrieval – often unencrypted"),
    143:  ("IMAP",       "Mail retrieval"),
    443:  ("HTTPS",      "Encrypted web traffic"),
    445:  ("SMB",        "Windows file sharing – frequent attack vector"),
    3306: ("MySQL",      "Database – should not be public"),
    3389: ("RDP",        "Remote Desktop – frequent attack vector"),
    5432: ("PostgreSQL", "Database – should not be public"),
    6379: ("Redis",      "Cache/DB – unauthenticated by default"),
    8080: ("HTTP-Alt",   "Alternate web / proxy"),
    8443: ("HTTPS-Alt",  "Alternate HTTPS"),
    27017:("MongoDB",    "Database – unauthenticated by default"),
}

HIGH_RISK_PORTS = {23, 445, 3389, 6379, 27017}
DB_PORTS        = {3306, 5432, 27017, 6379}

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def resolve_host(target: str) -> str | None:
    """Strip scheme/path and resolve to IP."""
    target = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def scan_port(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab a service banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(1024)
                return data.decode('utf-8', errors='replace').strip()[:200]
            except Exception:
                return ""
    except Exception:
        return ""


def check_ssl(host: str, port: int = 443) -> dict:
    """Inspect TLS certificate and cipher details."""
    result = {"enabled": False, "valid": False, "expiry": None,
              "days_left": None, "issues": [], "cipher": None, "version": None}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=4),
                             server_hostname=host) as s:
            result["enabled"] = True
            result["version"] = s.version()
            result["cipher"]  = s.cipher()[0] if s.cipher() else None
            cert = s.getpeercert()
            not_after = cert.get("notAfter", "")
            if not_after:
                exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                result["expiry"]    = exp.strftime("%Y-%m-%d")
                result["days_left"] = (exp - datetime.datetime.utcnow()).days
                result["valid"]     = result["days_left"] > 0
                if result["days_left"] < 30:
                    result["issues"].append(f"Certificate expires in {result['days_left']} days")
            if result["version"] in ("TLSv1", "TLSv1.1", "SSLv3"):
                result["issues"].append(f"Outdated TLS version: {result['version']}")
    except ssl.SSLCertVerificationError as e:
        result["enabled"] = True
        result["issues"].append(f"Certificate verification failed: {e.reason}")
    except Exception:
        pass
    return result


def check_http_headers(target: str) -> dict:
    """Fetch HTTP headers and audit security headers."""
    SECURITY_HEADERS = {
        "strict-transport-security": ("HSTS",                  "HIGH"),
        "content-security-policy":   ("Content-Security-Policy","HIGH"),
        "x-frame-options":           ("X-Frame-Options",        "MEDIUM"),
        "x-content-type-options":    ("X-Content-Type-Options", "MEDIUM"),
        "referrer-policy":           ("Referrer-Policy",        "LOW"),
        "permissions-policy":        ("Permissions-Policy",     "LOW"),
        "x-xss-protection":          ("X-XSS-Protection",       "LOW"),
    }
    result = {"reachable": False, "server": None, "powered_by": None,
              "missing_headers": [], "present_headers": [], "status_code": None}
    url = target if target.startswith("http") else f"http://{target}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VulnProbe/1.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            result["reachable"]   = True
            result["status_code"] = resp.status
            headers = {k.lower(): v for k, v in resp.headers.items()}
            result["server"]      = headers.get("server", "Not disclosed")
            result["powered_by"]  = headers.get("x-powered-by", None)
            for key, (name, severity) in SECURITY_HEADERS.items():
                if key in headers:
                    result["present_headers"].append({"name": name, "value": headers[key][:80]})
                else:
                    result["missing_headers"].append({"name": name, "severity": severity})
    except urllib.error.HTTPError as e:
        result["reachable"]   = True
        result["status_code"] = e.code
    except Exception:
        pass
    return result


def check_common_paths(host: str, port: int = 80, use_https: bool = False) -> list:
    """Check for exposed sensitive paths."""
    scheme = "https" if use_https else "http"
    SENSITIVE_PATHS = [
        ("/robots.txt",        "INFO",   "Robots.txt (may reveal hidden paths)"),
        ("/.env",              "CRITICAL","Exposed .env file (credentials!)"),
        ("/wp-admin/",         "MEDIUM", "WordPress admin panel"),
        ("/admin/",            "MEDIUM", "Admin panel"),
        ("/phpmyadmin/",       "HIGH",   "phpMyAdmin exposed"),
        ("/.git/config",       "CRITICAL","Git config exposed"),
        ("/server-status",     "MEDIUM", "Apache server-status"),
        ("/actuator",          "HIGH",   "Spring Boot actuator"),
        ("/api/v1/users",      "MEDIUM", "Unauthenticated API endpoint"),
        ("/config.php.bak",    "HIGH",   "Backup config file"),
    ]
    findings = []
    for path, severity, desc in SENSITIVE_PATHS:
        url = f"{scheme}://{host}:{port}{path}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "VulnProbe/1.0"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                if resp.status in (200, 403):
                    findings.append({
                        "path": path, "severity": severity,
                        "description": desc, "status": resp.status
                    })
        except Exception:
            pass
    return findings


# ─────────────────────────────────────────────
#  SEVERITY SCORING
# ─────────────────────────────────────────────
def compute_severity(port: int, banner: str) -> str:
    if port in HIGH_RISK_PORTS:
        return "CRITICAL"
    if port in DB_PORTS:
        return "HIGH"
    if port == 23:
        return "CRITICAL"
    if port == 21:
        return "HIGH"
    if port == 80:
        return "MEDIUM"
    return "LOW"


def severity_score(s: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(s, 0)


# ─────────────────────────────────────────────
#  MAIN SCAN LOGIC (streaming)
# ─────────────────────────────────────────────
def run_scan(target: str, scan_ports: bool, scan_headers: bool,
             scan_paths: bool, scan_ssl: bool):
    """Generator that yields SSE-formatted JSON events."""

    def emit(event_type: str, data: dict):
        return f"data: {json.dumps({'type': event_type, **data})}\n\n"

    yield emit("status", {"message": f"Resolving {target}…", "progress": 2})

    host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
    ip   = resolve_host(host)

    if not ip:
        yield emit("error", {"message": f"Cannot resolve host: {host}"})
        return

    yield emit("status", {"message": f"Host resolved → {ip}", "progress": 5})

    report = {
        "target": target, "host": host, "ip": ip,
        "scan_time": datetime.datetime.now().isoformat(),
        "open_ports": [], "ssl": {}, "headers": {},
        "sensitive_paths": [], "vulnerabilities": [],
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    }

    # ── PORT SCAN ──────────────────────────────
    if scan_ports:
        yield emit("status", {"message": "Scanning ports…", "progress": 10})
        ports = list(COMMON_PORTS.keys())
        results = []
        lock = threading.Lock()

        def check(p):
            if scan_port(ip, p):
                banner = grab_banner(ip, p)
                sev    = compute_severity(p, banner)
                entry  = {
                    "port": p,
                    "service": COMMON_PORTS[p][0],
                    "description": COMMON_PORTS[p][1],
                    "banner": banner or "—",
                    "severity": sev,
                    "risk_note": _port_risk_note(p)
                }
                with lock:
                    results.append(entry)

        threads = [threading.Thread(target=check, args=(p,)) for p in ports]
        for t in threads: t.start()
        for t in threads: t.join()

        results.sort(key=lambda x: x["port"])
        report["open_ports"] = results

        for r in results:
            yield emit("port_found", r)
            report["summary"][r["severity"].lower()] = \
                report["summary"].get(r["severity"].lower(), 0) + 1

        yield emit("status", {"message": f"Port scan complete — {len(results)} open", "progress": 40})

    # ── SSL CHECK ──────────────────────────────
    if scan_ssl:
        yield emit("status", {"message": "Inspecting TLS/SSL…", "progress": 50})
        ssl_data = check_ssl(host)
        report["ssl"] = ssl_data
        for issue in ssl_data["issues"]:
            sev = "HIGH" if "expired" in issue.lower() or "outdated" in issue.lower() else "MEDIUM"
            report["vulnerabilities"].append({"type": "SSL", "detail": issue, "severity": sev})
            report["summary"][sev.lower()] += 1
        yield emit("ssl_result", ssl_data)
        yield emit("status", {"message": "TLS check complete", "progress": 60})

    # ── HTTP HEADERS ───────────────────────────
    if scan_headers:
        yield emit("status", {"message": "Auditing HTTP security headers…", "progress": 65})
        hdr = check_http_headers(target if target.startswith("http") else f"http://{host}")
        report["headers"] = hdr
        for mh in hdr["missing_headers"]:
            sev = mh["severity"]
            report["vulnerabilities"].append({
                "type": "Missing Header",
                "detail": f"{mh['name']} not set",
                "severity": sev
            })
            report["summary"][sev.lower()] += 1
        if hdr.get("powered_by"):
            report["vulnerabilities"].append({
                "type": "Info Disclosure",
                "detail": f"X-Powered-By header exposes: {hdr['powered_by']}",
                "severity": "LOW"
            })
            report["summary"]["low"] += 1
        yield emit("headers_result", hdr)
        yield emit("status", {"message": "Header audit complete", "progress": 78})

    # ── SENSITIVE PATHS ────────────────────────
    if scan_paths:
        yield emit("status", {"message": "Probing sensitive paths…", "progress": 82})
        use_https = any(p["port"] == 443 for p in report["open_ports"]) if scan_ports else False
        port_to_use = 443 if use_https else 80
        paths = check_common_paths(host, port_to_use, use_https)
        report["sensitive_paths"] = paths
        for p in paths:
            sev = p["severity"]
            report["vulnerabilities"].append({
                "type": "Exposed Path",
                "detail": f"{p['path']} — {p['description']}",
                "severity": sev
            })
            report["summary"][sev.lower()] = report["summary"].get(sev.lower(), 0) + 1
        yield emit("paths_result", {"paths": paths})
        yield emit("status", {"message": "Path probe complete", "progress": 95})

    # ── DONE ───────────────────────────────────
    yield emit("status", {"message": "Scan complete!", "progress": 100})
    yield emit("done", {"report": report})


def _port_risk_note(port: int) -> str:
    notes = {
        21:    "FTP transmits credentials in plaintext. Prefer SFTP.",
        23:    "Telnet is unencrypted. Disable immediately.",
        25:    "SMTP open relay may allow spam abuse.",
        445:   "SMB is a common ransomware vector. Restrict access.",
        3306:  "MySQL should never be directly internet-accessible.",
        3389:  "RDP brute-force attacks are extremely common.",
        5432:  "PostgreSQL should be behind a firewall.",
        6379:  "Redis has no auth by default. Highly exploitable.",
        27017: "MongoDB had no auth by default until v3.0. Verify.",
        80:    "HTTP traffic is unencrypted. Prefer HTTPS.",
    }
    return notes.get(port, "Review necessity of this exposed service.")


# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan")
def scan():
    target      = request.args.get("target", "").strip()
    scan_ports  = request.args.get("ports",   "true") == "true"
    scan_ssl    = request.args.get("ssl",     "true") == "true"
    scan_headers= request.args.get("headers", "true") == "true"
    scan_paths  = request.args.get("paths",   "true") == "true"

    if not target:
        return jsonify({"error": "No target specified"}), 400

    def generate():
        yield "retry: 1000\n\n"
        for chunk in run_scan(target, scan_ports, scan_headers, scan_paths, scan_ssl):
            yield chunk

    return Response(stream_with_context(generate()),
                    content_type="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


if __name__ == "__main__":
    print("\n  ╔══════════════════════════════════╗")
    print("  ║   VulnProbe  —  localhost:5000   ║")
    print("  ╚══════════════════════════════════╝\n")
    app.run(debug=True, threaded=True)
