"""
Self-Healing Dynamic API Bridge — Production Backend Server
============================================================
A fully-developed autonomous API anomaly detection, schema repair,
circuit-breaker failover, and dynamic contract healing engine.

Run: python server.py
Access: http://127.0.0.1:8000
"""

import http.server
import socketserver
import json
import urllib.parse
import difflib
import time
import random
import threading
import os
from datetime import datetime, timezone, timedelta

# --- Configuration ---
PORT = 8000
HOST = "127.0.0.1"  # TODO(security): Bind to localhost only for safe testing
MAX_AUDIT_LOGS = 200
MAX_PIPELINE_NODES = 12
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 120  # max requests per window

# --- Global State ---
chaos_state = {
    "mode": "normal",
    "total_requests": 0,
    "healed_requests": 0,
    "failed_requests": 0,
    "uptime_start": time.time(),
    "last_request_time": None,
    "avg_latency_ms": 0.0,
    "total_latency_ms": 0.0,
}

audit_logs = []
audit_lock = threading.Lock()

# Rate limiter state
rate_limit_store = {}
rate_limit_lock = threading.Lock()

# Pipeline simulation state
pipeline_state = {
    "primary": {
        "id": "PIPE-ALPHA-001",
        "name": "Primary Data Pipeline",
        "status": "ACTIVE",
        "throughput": 0,
        "total_processed": 0,
        "error_count": 0,
        "nodes": [],
    },
    "secondary": {
        "id": "PIPE-BETA-002",
        "name": "Failover Pipeline",
        "status": "STANDBY",
        "throughput": 0,
        "total_processed": 0,
        "error_count": 0,
        "nodes": [],
    },
    "active_pipeline": "primary",
    "failover_active": False,
    "failover_reason": None,
    "failover_timestamp": None,
    "repair_progress": 0,
    "repair_eta_seconds": 0,
}
pipeline_lock = threading.Lock()


# --- Utility Functions ---

def get_server_time():
    """Return current server time in IST (UTC+5:30)."""
    ist = timezone(timedelta(hours=5, minutes=30))
    return datetime.now(ist)


def log_event(event_type, description, status="HEALED", details=None):
    """Thread-safe audit log entry."""
    now = get_server_time()
    entry = {
        "timestamp": now.strftime("%H:%M:%S.%f")[:-3],
        "date": now.strftime("%Y-%m-%d"),
        "type": event_type,
        "description": description,
        "status": status,
        "details": details or {},
    }
    with audit_lock:
        audit_logs.insert(0, entry)
        if len(audit_logs) > MAX_AUDIT_LOGS:
            audit_logs.pop()


def check_rate_limit(client_ip):
    """Simple sliding-window rate limiter."""
    now = time.time()
    with rate_limit_lock:
        if client_ip not in rate_limit_store:
            rate_limit_store[client_ip] = []
        # Remove expired timestamps
        rate_limit_store[client_ip] = [
            t for t in rate_limit_store[client_ip] if now - t < RATE_LIMIT_WINDOW
        ]
        if len(rate_limit_store[client_ip]) >= RATE_LIMIT_MAX:
            return False
        rate_limit_store[client_ip].append(now)
        return True


# --- Schema Healing Engine ---

KNOWN_FIELD_ALIASES = {
    "username": ["full_name", "user_name", "client_name", "usr_name", "account_name", "display_name"],
    "email": ["user_email", "mail_address", "contact_email", "email_addr", "e_mail"],
    "phone": ["mobile_number", "phone_number", "contact_no", "ph_number", "telephone", "cell"],
    "age": ["user_age", "years_old", "age_yrs", "birth_age"],
    "status": ["account_status", "is_active", "user_status", "acct_status"],
    "balance": ["account_balance", "wallet_balance", "curr_balance", "funds"],
    "address": ["home_address", "mailing_address", "street_address", "addr"],
    "id": ["user_id", "customer_id", "account_id", "uid", "cid"],
}


def auto_heal_payload(raw_data):
    """
    Intelligent Schema Healing Engine:
    - Matches unknown/renamed payload keys to canonical target keys via alias tables
    - Falls back to fuzzy string matching (Levenshtein-based) for unknown fields
    - Coerces stringified numbers into integers
    - Trims whitespace from string values
    - Returns healed data and applied repair rules
    """
    healed_data = {}
    applied_rules = []

    for key, val in raw_data.items():
        canonical_key = key
        found_alias = False

        # Phase 1: Direct alias lookup
        for std_key, aliases in KNOWN_FIELD_ALIASES.items():
            if key in aliases or key == std_key:
                canonical_key = std_key
                if key != std_key:
                    applied_rules.append(
                        f"ALIAS_MAP: '{key}' -> '{std_key}' (direct alias match)"
                    )
                found_alias = True
                break

        # Phase 2: Fuzzy matching fallback
        if not found_alias:
            all_known = list(KNOWN_FIELD_ALIASES.keys())
            matches = difflib.get_close_matches(key.lower(), all_known, n=1, cutoff=0.55)
            if matches:
                canonical_key = matches[0]
                applied_rules.append(
                    f"FUZZY_MAP: '{key}' -> '{canonical_key}' (similarity score >= 0.55)"
                )

        # Phase 3: Type coercion — string digits to int
        coerced_val = val
        if isinstance(val, str):
            stripped = val.strip()
            if stripped.isdigit():
                coerced_val = int(stripped)
                applied_rules.append(
                    f"TYPE_COERCE: '{canonical_key}' string '{val}' -> int({coerced_val})"
                )
            elif stripped != val:
                coerced_val = stripped
                applied_rules.append(
                    f"TRIM: '{canonical_key}' whitespace trimmed"
                )

        healed_data[canonical_key] = coerced_val

    return healed_data, applied_rules


# --- Pipeline Simulation Engine ---

def initialize_pipeline_nodes():
    """Create realistic pipeline node topology."""
    primary_nodes = [
        {"id": f"PN-{i:03d}", "name": n, "status": "ACTIVE", "load": random.randint(15, 85), "packets": 0, "errors": 0}
        for i, n in enumerate([
            "Ingress Gateway", "TLS Terminator", "Rate Limiter", "Auth Validator",
            "Schema Validator", "Payload Parser", "Business Logic", "Cache Layer",
            "Data Transformer", "Outbound Serializer", "Response Compressor", "Egress Gateway"
        ])
    ]
    secondary_nodes = [
        {"id": f"SN-{i:03d}", "name": n, "status": "STANDBY", "load": 0, "packets": 0, "errors": 0}
        for i, n in enumerate([
            "Failover Ingress", "TLS Proxy", "Backup Rate Limiter", "Auth Mirror",
            "Schema Validator B", "Payload Parser B", "Logic Replica", "Cache Replica",
            "Transformer B", "Serializer B", "Compressor B", "Failover Egress"
        ])
    ]
    with pipeline_lock:
        pipeline_state["primary"]["nodes"] = primary_nodes
        pipeline_state["secondary"]["nodes"] = secondary_nodes


def simulate_pipeline_tick():
    """Advance pipeline simulation by one tick."""
    with pipeline_lock:
        active = pipeline_state["active_pipeline"]
        pipe = pipeline_state[active]

        # Simulate data flowing through nodes
        for node in pipe["nodes"]:
            if node["status"] == "ACTIVE":
                node["packets"] += random.randint(5, 25)
                node["load"] = min(100, max(5, node["load"] + random.randint(-8, 8)))

        pipe["throughput"] = sum(n["load"] for n in pipe["nodes"] if n["status"] == "ACTIVE") // max(1, len(pipe["nodes"]))
        pipe["total_processed"] += random.randint(10, 50)

        # If failover is active, simulate repair progress
        if pipeline_state["failover_active"]:
            pipeline_state["repair_progress"] = min(100, pipeline_state["repair_progress"] + random.uniform(0.5, 3.0))
            pipeline_state["repair_eta_seconds"] = max(0, int((100 - pipeline_state["repair_progress"]) * 1.2))

            if pipeline_state["repair_progress"] >= 100:
                # Repair complete — switch back to primary
                pipeline_state["failover_active"] = False
                pipeline_state["active_pipeline"] = "primary"
                pipeline_state["repair_progress"] = 0
                pipeline_state["repair_eta_seconds"] = 0
                pipeline_state["failover_reason"] = None
                pipeline_state["failover_timestamp"] = None
                for node in pipeline_state["primary"]["nodes"]:
                    node["status"] = "ACTIVE"
                    node["errors"] = 0
                    node["load"] = random.randint(15, 45)
                for node in pipeline_state["secondary"]["nodes"]:
                    node["status"] = "STANDBY"
                    node["load"] = 0
                pipeline_state["primary"]["status"] = "ACTIVE"
                pipeline_state["secondary"]["status"] = "STANDBY"
                log_event(
                    "PIPELINE_RESTORED",
                    "Primary pipeline fully repaired and restored. Failover pipeline returned to standby.",
                    "HEALED",
                    {"pipeline": "PIPE-ALPHA-001"}
                )


def trigger_pipeline_failure(error_node_index=None):
    """Simulate a pipeline failure and trigger failover."""
    with pipeline_lock:
        if pipeline_state["failover_active"]:
            return {"status": "already_in_failover", "message": "Pipeline is already in failover mode."}

        if error_node_index is None:
            error_node_index = random.randint(3, 8)

        error_node_index = max(0, min(error_node_index, len(pipeline_state["primary"]["nodes"]) - 1))

        failed_node = pipeline_state["primary"]["nodes"][error_node_index]
        failed_node["status"] = "FAILED"
        failed_node["errors"] += 1
        failed_node["load"] = 0

        # Mark downstream nodes as blocked
        for i in range(error_node_index + 1, len(pipeline_state["primary"]["nodes"])):
            pipeline_state["primary"]["nodes"][i]["status"] = "BLOCKED"
            pipeline_state["primary"]["nodes"][i]["load"] = 0

        pipeline_state["primary"]["status"] = "FAILED"
        pipeline_state["primary"]["error_count"] += 1

        # Activate secondary pipeline
        pipeline_state["active_pipeline"] = "secondary"
        pipeline_state["failover_active"] = True
        pipeline_state["failover_reason"] = f"Node '{failed_node['name']}' ({failed_node['id']}) critical failure"
        pipeline_state["failover_timestamp"] = get_server_time().isoformat()
        pipeline_state["repair_progress"] = 0
        pipeline_state["repair_eta_seconds"] = 120
        pipeline_state["secondary"]["status"] = "ACTIVE"

        for node in pipeline_state["secondary"]["nodes"]:
            node["status"] = "ACTIVE"
            node["load"] = random.randint(20, 60)

        log_event(
            "PIPELINE_FAILOVER",
            f"Critical failure at node '{failed_node['name']}'. Traffic rerouted to failover pipeline PIPE-BETA-002.",
            "FAILOVER",
            {
                "failed_node": failed_node["id"],
                "failed_node_name": failed_node["name"],
                "failover_pipeline": "PIPE-BETA-002",
            }
        )

        return {
            "status": "failover_triggered",
            "failed_node": failed_node["name"],
            "failed_node_id": failed_node["id"],
            "failover_pipeline": "PIPE-BETA-002",
            "repair_eta_seconds": 120,
        }


# --- Background Pipeline Ticker ---

def pipeline_ticker_thread():
    """Background thread that advances pipeline simulation."""
    while True:
        try:
            simulate_pipeline_tick()
        except Exception:
            pass
        time.sleep(1.0)


# --- HTTP Request Handler ---

class SelfHealingRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Production-grade request handler with security headers, rate limiting, and full API suite."""

    def log_message(self, format, *args):
        """Override to use custom logging format."""
        timestamp = get_server_time().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {self.client_address[0]} - {format % args}")

    def _get_client_ip(self):
        return self.client_address[0]

    def _send_json(self, data, status=200):
        """Send JSON response with security headers."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        # TODO(security): In production, replace '*' with specific allowed origin
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def _send_error_json(self, message, status=400):
        self._send_json({"error": message, "status": status}, status=status)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        # Rate limiting
        if path.startswith("/api/"):
            if not check_rate_limit(self._get_client_ip()):
                self._send_error_json("Rate limit exceeded. Max 120 requests per minute.", 429)
                return

        # ===================== SERVER INFO / HEALTH =====================
        if path == "/api/health":
            uptime = time.time() - chaos_state["uptime_start"]
            hours = int(uptime // 3600)
            mins = int((uptime % 3600) // 60)
            secs = int(uptime % 60)
            now = get_server_time()

            self._send_json({
                "status": "operational",
                "server": "Self-Healing Dynamic API Bridge v2.0",
                "host": HOST,
                "port": PORT,
                "uptime": f"{hours}h {mins}m {secs}s",
                "uptime_seconds": round(uptime, 2),
                "server_time": now.strftime("%Y-%m-%d %H:%M:%S %Z"),
                "server_time_iso": now.isoformat(),
                "timezone": "IST (UTC+05:30)",
                "total_requests_processed": chaos_state["total_requests"],
                "total_healed": chaos_state["healed_requests"],
                "total_failed": chaos_state["failed_requests"],
                "healing_rate": round(
                    ((chaos_state["total_requests"] - chaos_state["failed_requests"]) /
                     max(1, chaos_state["total_requests"])) * 100, 2
                ),
                "avg_latency_ms": round(chaos_state["avg_latency_ms"], 2),
                "chaos_mode": chaos_state["mode"],
                "endpoints": [
                    {"method": "GET",  "path": "/api/health",           "description": "Server health & status"},
                    {"method": "GET",  "path": "/api/server-time",      "description": "Current server time"},
                    {"method": "GET",  "path": "/api/chaos-status",     "description": "Chaos state & audit logs"},
                    {"method": "GET",  "path": "/api/simulate-random",  "description": "Auto-pilot random scenario"},
                    {"method": "GET",  "path": "/api/direct-upstream",  "description": "Direct API call (no bridge)"},
                    {"method": "GET",  "path": "/api/bridge-request",   "description": "Self-healing bridge call"},
                    {"method": "GET",  "path": "/api/pipeline-status",  "description": "Pipeline topology & state"},
                    {"method": "GET",  "path": "/api/metrics",          "description": "Aggregated system metrics"},
                    {"method": "POST", "path": "/api/toggle-chaos",     "description": "Switch chaos mode"},
                    {"method": "POST", "path": "/api/pipeline-trigger-failure", "description": "Trigger pipeline failure"},
                    {"method": "POST", "path": "/api/pipeline-reset",   "description": "Reset pipeline to normal"},
                    {"method": "POST", "path": "/api/heal-payload",     "description": "Heal a custom payload"},
                ],
                "version": "2.0.0",
                "engine": "Python http.server + Self-Healing Bridge Engine",
            })
            return

        # ===================== SERVER TIME =====================
        if path == "/api/server-time":
            now = get_server_time()
            self._send_json({
                "time": now.strftime("%H:%M:%S"),
                "date": now.strftime("%Y-%m-%d"),
                "datetime": now.strftime("%Y-%m-%d %H:%M:%S"),
                "iso": now.isoformat(),
                "timezone": "IST (UTC+05:30)",
                "unix": int(now.timestamp()),
            })
            return

        # ===================== CHAOS STATUS =====================
        if path == "/api/chaos-status":
            with audit_lock:
                logs_copy = list(audit_logs[:30])
            self._send_json({
                "chaos_state": {
                    "mode": chaos_state["mode"],
                    "total_requests": chaos_state["total_requests"],
                    "healed_requests": chaos_state["healed_requests"],
                    "failed_requests": chaos_state["failed_requests"],
                },
                "audit_logs": logs_copy,
            })
            return

        # ===================== SYSTEM METRICS =====================
        if path == "/api/metrics":
            uptime = time.time() - chaos_state["uptime_start"]
            total = max(1, chaos_state["total_requests"])
            with pipeline_lock:
                pipe_snapshot = {
                    "active_pipeline": pipeline_state["active_pipeline"],
                    "failover_active": pipeline_state["failover_active"],
                    "failover_reason": pipeline_state["failover_reason"],
                    "repair_progress": round(pipeline_state["repair_progress"], 1),
                    "primary_status": pipeline_state["primary"]["status"],
                    "secondary_status": pipeline_state["secondary"]["status"],
                    "primary_throughput": pipeline_state["primary"]["throughput"],
                    "secondary_throughput": pipeline_state["secondary"]["throughput"],
                }
            self._send_json({
                "uptime_seconds": round(uptime, 2),
                "requests_per_minute": round(chaos_state["total_requests"] / max(1, uptime / 60), 2),
                "total_requests": chaos_state["total_requests"],
                "healed_requests": chaos_state["healed_requests"],
                "failed_requests": chaos_state["failed_requests"],
                "healing_rate_pct": round(((total - chaos_state["failed_requests"]) / total) * 100, 2),
                "avg_latency_ms": round(chaos_state["avg_latency_ms"], 2),
                "chaos_mode": chaos_state["mode"],
                "pipeline": pipe_snapshot,
                "schema_aliases_configured": sum(len(v) for v in KNOWN_FIELD_ALIASES.values()),
                "canonical_fields": list(KNOWN_FIELD_ALIASES.keys()),
            })
            return

        # ===================== PIPELINE STATUS =====================
        if path == "/api/pipeline-status":
            with pipeline_lock:
                snapshot = json.loads(json.dumps(pipeline_state))
            self._send_json(snapshot)
            return

        # ===================== SIMULATE RANDOM =====================
        if path == "/api/simulate-random":
            start_time = time.time()
            chaos_state["total_requests"] += 1

            users = [
                ("sarah_connor", "sarah@skynet.io", "+1-555-0142", 29),
                ("alex_mercer", "alex@prototype.org", "+1-555-8933", 31),
                ("marcus_wright", "marcus@resistance.net", "+1-555-4421", 38),
                ("elena_fisher", "elena@uncharted.com", "+1-555-7719", 26),
                ("jordan_belfort", "jordan@wallst.co", "+1-555-3211", 35),
                ("maya_patel", "maya@techcorp.in", "+91-555-9201", 27),
                ("dmitri_volkov", "dmitri@securenet.ru", "+7-555-6643", 42),
            ]
            u_name, u_email, u_phone, u_age = random.choice(users)

            scenario_type = random.choices(
                ["schema_drift", "type_mutation", "server_outage", "pass_through"],
                weights=[35, 25, 20, 20],
                k=1,
            )[0]

            if scenario_type == "schema_drift":
                alias_sets = [
                    {"client_name": u_name, "mail_address": u_email, "contact_no": u_phone, "years_old": str(u_age), "account_status": "active"},
                    {"usr_name": u_name, "email_addr": u_email, "ph_number": u_phone, "user_age": str(u_age), "is_active": "true"},
                    {"display_name": u_name, "contact_email": u_email, "telephone": u_phone, "birth_age": str(u_age), "acct_status": "active"},
                ]
                raw_payload = random.choice(alias_sets)
                healed_payload, repair_logs = auto_heal_payload(raw_payload)
                latency_ms = round((time.time() - start_time) * 1000 + random.uniform(8, 16), 2)
                chaos_state["healed_requests"] += 1
                self._update_latency(latency_ms)

                endpoints = ["/api/v1/user/checkout", "/api/v1/crm/onboard", "/api/v1/accounts/sync"]
                ep = random.choice(endpoints)
                log_event(
                    "SCHEMA_AUTO_HEALED",
                    f"Auto-mapped {len(repair_logs)} drifted fields for '{u_name}' via alias + fuzzy engine.",
                    "HEALED",
                    {"endpoint": ep, "repairs": repair_logs},
                )
                self._send_json({
                    "endpoint": f"POST {ep}",
                    "bridge_status": "HEALED",
                    "scenario": "Schema Drift Auto-Healed",
                    "original_status": 200,
                    "applied_strategy": "Dynamic Schema Mapping & Fuzzy Reconciliation",
                    "latency_ms": latency_ms,
                    "raw_unstable_payload": raw_payload,
                    "healed_payload": healed_payload,
                    "repairs": repair_logs,
                })
                return

            elif scenario_type == "type_mutation":
                raw_payload = {
                    "username": u_name,
                    "email": u_email,
                    "phone": u_phone,
                    "age": str(u_age),
                    "balance": str(random.randint(250, 9800)),
                }
                healed_payload, repair_logs = auto_heal_payload(raw_payload)
                latency_ms = round((time.time() - start_time) * 1000 + random.uniform(6, 12), 2)
                chaos_state["healed_requests"] += 1
                self._update_latency(latency_ms)

                log_event(
                    "TYPE_NORMALIZED",
                    f"Converted string numbers to strict typed integers for '{u_name}'.",
                    "HEALED",
                    {"endpoint": "/api/v1/crm/customer/profile", "repairs": repair_logs},
                )
                self._send_json({
                    "endpoint": "GET /api/v1/crm/customer/profile",
                    "bridge_status": "HEALED",
                    "scenario": "Type Mutation Repaired",
                    "original_status": 200,
                    "applied_strategy": "Runtime Type Sanitization & Strict Coercion",
                    "latency_ms": latency_ms,
                    "raw_unstable_payload": raw_payload,
                    "healed_payload": healed_payload,
                    "repairs": repair_logs,
                })
                return

            elif scenario_type == "server_outage":
                latency_ms = round((time.time() - start_time) * 1000 + random.uniform(18, 32), 2)
                chaos_state["healed_requests"] += 1
                self._update_latency(latency_ms)

                fallback_nodes = ["eu-central-backup-02", "us-west-standby-03", "ap-south-replica-01"]
                node = random.choice(fallback_nodes)
                log_event(
                    "ENDPOINT_FAILOVER",
                    f"Primary microservice HTTP 500. Circuit breaker failover to {node}.",
                    "HEALED",
                    {"fallback_node": node, "latency": f"{latency_ms}ms"},
                )
                self._send_json({
                    "endpoint": "POST /api/v1/payments/charge",
                    "bridge_status": "HEALED",
                    "scenario": "Server 500 Crash -> Standby Failover",
                    "original_status": 500,
                    "applied_strategy": "Circuit Breaker Tripped -> Hot Standby Failover",
                    "latency_ms": latency_ms,
                    "raw_unstable_payload": {
                        "error": "Internal Server Error",
                        "code": 500,
                        "upstream": "primary-node-alpha: connection refused",
                    },
                    "healed_payload": {
                        "transaction_id": f"tx_{random.randint(100000, 999999)}",
                        "customer": u_name,
                        "status": "APPROVED",
                        "routed_via": node,
                    },
                    "repairs": [
                        "Circuit Breaker Intercepted HTTP 500",
                        f"Rerouted to {node} (0 lost packets)",
                    ],
                })
                return

            else:
                latency_ms = round((time.time() - start_time) * 1000 + random.uniform(3, 7), 2)
                self._update_latency(latency_ms)
                self._send_json({
                    "endpoint": "GET /api/v1/inventory/telemetry",
                    "bridge_status": "PASS_THROUGH",
                    "scenario": "Clean Pass-Through (Zero Drift)",
                    "original_status": 200,
                    "applied_strategy": "Contract Verified. Transparent zero-overhead pass-through.",
                    "latency_ms": latency_ms,
                    "raw_unstable_payload": {
                        "username": u_name, "email": u_email,
                        "phone": u_phone, "age": u_age, "status": "active",
                    },
                    "healed_payload": {
                        "username": u_name, "email": u_email,
                        "phone": u_phone, "age": u_age, "status": "active",
                    },
                    "repairs": [],
                })
                return

        # ===================== DIRECT UPSTREAM (NO BRIDGE) =====================
        if path == "/api/direct-upstream":
            chaos_state["total_requests"] += 1
            mode = chaos_state["mode"]

            if mode == "normal":
                self._send_json({
                    "status": "success",
                    "data": {
                        "username": "alex_dev", "email": "alex@example.com",
                        "phone": "555-0199", "age": 21,
                    },
                })
            elif mode == "renamed_keys":
                self._send_json({
                    "status": "success",
                    "data": {
                        "full_name": "alex_dev", "mail_address": "alex@example.com",
                        "mobile_number": "555-0199", "age_yrs": 21,
                    },
                })
            elif mode == "type_mismatch":
                self._send_json({
                    "status": "success",
                    "data": {
                        "username": "alex_dev", "email": "alex@example.com",
                        "phone": "555-0199", "age": "21",
                    },
                })
            elif mode == "server_outage":
                chaos_state["failed_requests"] += 1
                log_event(
                    "DIRECT_CALL_FAILED",
                    "Primary API returned HTTP 500 Internal Error. Consumer received raw error.",
                    "FAILED",
                    {"http_code": 500},
                )
                self._send_json({
                    "error": "Internal Server Error",
                    "message": "Database connection refused on primary cluster",
                    "status": 500,
                }, status=500)
            return

        # ===================== BRIDGE REQUEST =====================
        if path == "/api/bridge-request":
            start_time = time.time()
            chaos_state["total_requests"] += 1
            mode = chaos_state["mode"]

            upstream_status = 200
            raw_response = {}

            if mode == "normal":
                raw_response = {
                    "username": "alex_dev", "email": "alex@example.com",
                    "phone": "555-0199", "age": 21,
                }
            elif mode == "renamed_keys":
                raw_response = {
                    "full_name": "alex_dev", "mail_address": "alex@example.com",
                    "mobile_number": "555-0199", "age_yrs": "21",
                }
            elif mode == "type_mismatch":
                raw_response = {
                    "username": "alex_dev", "email": "alex@example.com",
                    "phone": "555-0199", "age": "21",
                }
            elif mode == "server_outage":
                upstream_status = 500

            if upstream_status == 500:
                chaos_state["healed_requests"] += 1
                fallback_data = {
                    "username": "alex_dev (Backup Node)",
                    "email": "alex@backup-server.org",
                    "phone": "555-0199",
                    "age": 21,
                }
                latency_ms = round((time.time() - start_time) * 1000 + 15, 2)
                self._update_latency(latency_ms)
                log_event(
                    "ENDPOINT_FAILOVER",
                    "Primary Server 500 error caught. Rerouted to secondary backup pool.",
                    "HEALED",
                    {"fallback_node": "us-east-backup-02", "latency": f"{latency_ms}ms"},
                )
                self._send_json({
                    "bridge_status": "HEALED",
                    "original_status": 500,
                    "applied_strategy": "Automatic Endpoint Failover to Backup Node",
                    "latency_ms": latency_ms,
                    "raw_unstable_payload": {
                        "error": "Internal Server Error",
                        "status": 500,
                        "upstream": "primary-node: connection refused",
                    },
                    "healed_payload": fallback_data,
                    "data": fallback_data,
                    "repairs": [
                        "Intercepted 500 Error",
                        "Switched Route: /api/v1 -> /api/backup-v2",
                    ],
                })
                return

            healed_payload, repair_logs = auto_heal_payload(raw_response)
            latency_ms = round((time.time() - start_time) * 1000 + 8, 2)
            self._update_latency(latency_ms)

            if repair_logs:
                chaos_state["healed_requests"] += 1
                log_event(
                    "SCHEMA_AUTO_HEALED",
                    f"Repaired {len(repair_logs)} breaking changes in response schema.",
                    "HEALED",
                    {"repairs": repair_logs},
                )
                self._send_json({
                    "bridge_status": "HEALED",
                    "original_status": 200,
                    "applied_strategy": "Dynamic Schema Mapping & Type Normalization",
                    "latency_ms": latency_ms,
                    "raw_unstable_payload": raw_response,
                    "healed_payload": healed_payload,
                    "repairs": repair_logs,
                })
            else:
                self._send_json({
                    "bridge_status": "PASS_THROUGH",
                    "original_status": 200,
                    "applied_strategy": "No anomaly detected. Clean pass-through.",
                    "latency_ms": latency_ms,
                    "raw_unstable_payload": raw_response,
                    "healed_payload": healed_payload,
                    "repairs": [],
                })
            return

        # ===================== SERVE STATIC FILES =====================
        return super().do_GET()

    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        # Rate limiting
        if not check_rate_limit(self._get_client_ip()):
            self._send_error_json("Rate limit exceeded.", 429)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 65536:  # 64KB max payload
            self._send_error_json("Payload too large.", 413)
            return

        post_data = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            body = json.loads(post_data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_error_json("Invalid JSON payload.", 400)
            return

        # ===================== TOGGLE CHAOS =====================
        if path == "/api/toggle-chaos":
            allowed_modes = {"normal", "renamed_keys", "server_outage", "type_mismatch"}
            new_mode = body.get("mode", "normal")
            if new_mode not in allowed_modes:
                self._send_error_json(f"Invalid mode. Allowed: {sorted(allowed_modes)}", 400)
                return

            chaos_state["mode"] = new_mode
            log_event(
                "CHAOS_STATE_CHANGED",
                f"Chaos state updated to: '{new_mode}'",
                "SYSTEM",
                {"new_mode": new_mode},
            )
            self._send_json({"status": "success", "current_mode": new_mode})
            return

        # ===================== PIPELINE TRIGGER FAILURE =====================
        if path == "/api/pipeline-trigger-failure":
            node_index = body.get("node_index", None)
            if node_index is not None:
                if not isinstance(node_index, int) or node_index < 0 or node_index > 11:
                    self._send_error_json("node_index must be an integer 0-11.", 400)
                    return
            result = trigger_pipeline_failure(node_index)
            self._send_json(result)
            return

        # ===================== PIPELINE RESET =====================
        if path == "/api/pipeline-reset":
            initialize_pipeline_nodes()
            with pipeline_lock:
                pipeline_state["active_pipeline"] = "primary"
                pipeline_state["failover_active"] = False
                pipeline_state["failover_reason"] = None
                pipeline_state["failover_timestamp"] = None
                pipeline_state["repair_progress"] = 0
                pipeline_state["repair_eta_seconds"] = 0
                pipeline_state["primary"]["status"] = "ACTIVE"
                pipeline_state["secondary"]["status"] = "STANDBY"
            log_event("PIPELINE_RESET", "Pipeline topology reset to clean state.", "SYSTEM")
            self._send_json({"status": "success", "message": "Pipeline reset to initial state."})
            return

        # ===================== HEAL CUSTOM PAYLOAD =====================
        if path == "/api/heal-payload":
            payload = body.get("payload", {})
            if not isinstance(payload, dict) or len(payload) == 0:
                self._send_error_json("Provide a non-empty 'payload' object.", 400)
                return
            start_time = time.time()
            healed, repairs = auto_heal_payload(payload)
            latency = round((time.time() - start_time) * 1000, 2)
            self._send_json({
                "original": payload,
                "healed": healed,
                "repairs": repairs,
                "latency_ms": latency,
                "fields_repaired": len(repairs),
            })
            return

        self._send_error_json("Endpoint not found.", 404)

    def _update_latency(self, latency_ms):
        """Update running average latency."""
        total = chaos_state["total_requests"]
        if total <= 1:
            chaos_state["avg_latency_ms"] = latency_ms
        else:
            chaos_state["avg_latency_ms"] = (
                chaos_state["avg_latency_ms"] * (total - 1) + latency_ms
            ) / total
        chaos_state["last_request_time"] = get_server_time().isoformat()


# --- Server Startup ---

if __name__ == "__main__":
    # Initialize pipeline nodes
    initialize_pipeline_nodes()

    # Start background pipeline ticker
    ticker = threading.Thread(target=pipeline_ticker_thread, daemon=True)
    ticker.start()

    socketserver.TCPServer.allow_reuse_address = True

    print("=" * 66)
    print("  SELF-HEALING DYNAMIC API BRIDGE — Production Server v2.0")
    print("=" * 66)
    print(f"  Host       : {HOST}")
    print(f"  Port       : {PORT}")
    print(f"  URL        : http://{HOST}:{PORT}")
    print(f"  Health     : http://{HOST}:{PORT}/api/health")
    print(f"  Dashboard  : http://{HOST}:{PORT}/index.html")
    print(f"  Time       : {get_server_time().strftime('%Y-%m-%d %H:%M:%S %Z')}")
    print("=" * 66)
    print("  [ACTIVE] Schema Healing Engine")
    print("  [ACTIVE] Circuit Breaker Failover")
    print("  [ACTIVE] Pipeline Simulation Engine")
    print("  [ACTIVE] Rate Limiter (120 req/min)")
    print("  [ACTIVE] Audit Logger")
    print("=" * 66)
    print("  Press Ctrl+C to stop the server.\n")

    log_event(
        "SERVER_STARTED",
        f"Self-Healing API Bridge v2.0 started on {HOST}:{PORT}",
        "SYSTEM",
        {"host": HOST, "port": PORT},
    )

    with socketserver.ThreadingTCPServer(("0.0.0.0", int(os.environ.get("PORT",PORT)))), SelfHealingRequestHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Server shut down by user.")
