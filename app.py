"""
Intelligent pfSense Firewall Monitor
Backend: Flask REST API
Author: Your Name
"""

import re, json, math, time, logging, threading
from datetime import datetime
from collections import Counter
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple
from flask import Flask, jsonify, request, Response
from flask_cors import CORS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger("pfsense")

try:    import paramiko;                          SSH_OK = True
except: SSH_OK = False; log.warning("paramiko not installed")

try:
    from sklearn.ensemble import IsolationForest; ML_OK = True
except: ML_OK = False; log.warning("sklearn not installed")

try:    import anthropic;                         LLM_OK = True
except: LLM_OK = False

# ── CONFIG ─────────────────────────────────────────────────────────────────────
config = {
    "fw_host":        "192.168.1.1",   # Your pfSense IP
    "fw_port":        22,
    "fw_user":        "admin",
    "fw_password":    "",              # Set your pfSense password
    "interval_min":   5,
    "demo_mode":      True,            # Set False for real pfSense
    "anthropic_key":  "",              # Optional: Claude API key
    "critical_ports": [22, 23, 3306, 5432, 3389, 445, 1433, 8080, 27017, 6379],
    "critical_nets":  ["10.", "192.168."],
}

# ── DATA MODELS ────────────────────────────────────────────────────────────────
@dataclass
class FWEvent:
    action:   str
    proto:    str
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    iface:    str
    raw:      str

@dataclass
class RiskReport:
    timestamp:          str
    window_min:         int
    total:              int
    blocked:            int
    allowed:            int
    unique_src:         int
    top_ports:          List[int]
    exploit_likelihood: float
    attack_surface:     float
    asset_criticality:  float
    rule_violation:     float
    traffic_anomaly:    float
    risk_score:         float
    severity:           str
    threats:            List[dict]
    llm_explanation:    str
    llm_fix:            str

# ── LOG COLLECTOR ──────────────────────────────────────────────────────────────
class Collector:

    def collect(self) -> List[str]:
        if config["demo_mode"] or not SSH_OK:
            log.info("Demo mode — using simulated logs")
            return self._demo()
        try:
            log.info(f"Connecting to pfSense {config['fw_host']} via SSH...")
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(
                hostname=config["fw_host"],
                port=int(config["fw_port"]),
                username=config["fw_user"],
                password=config["fw_password"],
                timeout=15,
                banner_timeout=20,
                look_for_keys=False,
                allow_agent=False,
            )
            cmd = (
                "clog /var/log/filter.log 2>/dev/null | tail -n 500 || "
                "tail -n 500 /var/log/filter.log 2>/dev/null"
            )
            _, o, e = c.exec_command(cmd, timeout=30)
            lines = o.read().decode(errors="ignore").splitlines()
            err   = e.read().decode(errors="ignore").strip()
            c.close()
            if err:
                log.warning(f"pfSense stderr: {err[:150]}")
            log.info(f"SSH: {len(lines)} lines from {config['fw_host']}")
            if len(lines) == 0:
                log.warning("No lines — enable: Status > System Logs > Settings > Log packets")
                return self._demo()
            return lines
        except paramiko.AuthenticationException:
            log.error("SSH AUTH FAILED — check username/password")
            return self._demo()
        except Exception as e:
            log.error(f"SSH error: {e}")
            return self._demo()

    def block_ip(self, ip: str) -> Tuple[bool, str]:
        if config["demo_mode"]:
            return True, f"[DEMO] pfctl -t blocklist -T add {ip}"
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(
                hostname=config["fw_host"],
                port=int(config["fw_port"]),
                username=config["fw_user"],
                password=config["fw_password"],
                timeout=15,
                look_for_keys=False,
            )
            _, o, e = c.exec_command(f"pfctl -t blocklist -T add {ip}")
            out = o.read().decode().strip()
            err = e.read().decode().strip()
            c.close()
            if "error" in err.lower():
                return False, err
            return True, f"Blocked {ip} on pfSense. {out}"
        except Exception as e:
            return False, str(e)

    def _demo(self) -> List[str]:
        import random
        now  = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        atk  = ["45.33.32.156", "198.20.70.114", "80.82.77.139",
                 "5.188.206.14", "194.165.16.11"]
        norm = [f"172.16.{random.randint(0,3)}.{random.randint(2,254)}"
                for _ in range(15)]
        lines = []
        for _ in range(random.randint(300, 700)):
            is_atk = random.random() < 0.35
            src    = random.choice(atk if is_atk else norm)
            dst    = f"192.168.1.{random.randint(1, 20)}"
            act    = "block" if is_atk else random.choice(["pass", "pass", "block"])
            dp     = random.choice(
                [22, 80, 443, 3306, 8080, 53, 21, 23, 3389] if is_atk
                else [80, 443, 53]
            )
            sp    = random.randint(1024, 65535)
            proto = random.choice(["tcp", "udp", "icmp"])
            lines.append(
                f"<134>1 {now} firewall filterlog - - - "
                f"100,,,1000000103,em0,match,{act},in,4,0x0,,64,"
                f"{random.randint(1000,60000)},0,none,6,{proto},60,"
                f"{src},{dst},{sp},{dp},SA,255"
            )
        return lines

# ── LOG PARSER ─────────────────────────────────────────────────────────────────
class Parser:
    """Parse pfSense filterlog CSV format."""

    PAT = re.compile(
        r"filterlog.*?-\s+(?:\d+),(?:[^,]*),(?:[^,]*),(?:[^,]*),"
        r"(?P<iface>\w+),(?:[^,]*),"
        r"(?P<action>block|pass),(?:in|out),(?:\d),"
        r"(?:[^,]*,){7}(?P<proto>\w+),(?:[^,]*),"
        r"(?P<src>[\d.]+),(?P<dst>[\d.]+)"
        r"(?:,(?P<sp>\d+),(?P<dp>\d+))?",
        re.IGNORECASE
    )

    def parse(self, lines: List[str]) -> List[FWEvent]:
        events = []
        for line in lines:
            m = self.PAT.search(line)
            if m:
                events.append(FWEvent(
                    action   = m.group("action").lower(),
                    proto    = m.group("proto").upper(),
                    src_ip   = m.group("src"),
                    dst_ip   = m.group("dst"),
                    src_port = int(m.group("sp") or 0),
                    dst_port = int(m.group("dp") or 0),
                    iface    = m.group("iface"),
                    raw      = line[:150],
                ))
        log.info(f"Parsed {len(events)}/{len(lines)} lines")
        return events

# ── FEATURE EXTRACTOR ──────────────────────────────────────────────────────────
class FeatureExtractor:
    """Extract numerical features from firewall events."""

    def extract(self, events: List[FWEvent]) -> Dict:
        if not events:
            return self._empty()

        total   = len(events)
        blocked = sum(1 for e in events if e.action == "block")
        ip_cnt  = Counter(e.src_ip for e in events)
        pt_cnt  = Counter(e.dst_port for e in events if e.dst_port)
        top_pts = [p for p, _ in pt_cnt.most_common(10)]

        # Port scan: 1 IP → 10+ different destination ports
        port_scan_ips = []
        for ip in ip_cnt:
            ports = set(e.dst_port for e in events if e.src_ip == ip and e.dst_port)
            if len(ports) >= 10:
                port_scan_ips.append({"ip": ip, "ports": sorted(ports)[:15]})

        # Brute force: 1 IP → 50+ blocked connections
        brute_ips = []
        for ip, cnt in ip_cnt.items():
            if cnt >= 50:
                bl = sum(1 for e in events if e.src_ip == ip and e.action == "block")
                if bl >= 30:
                    brute_ips.append({"ip": ip, "attempts": cnt})

        # Critical asset hits
        cp   = set(config["critical_ports"])
        cn   = config["critical_nets"]
        crit = sum(
            1 for e in events
            if e.dst_port in cp or any(e.dst_ip.startswith(n) for n in cn)
        )

        return {
            "total":          total,
            "blocked":        blocked,
            "allowed":        total - blocked,
            "block_rate":     blocked / total,
            "unique_src":     len(ip_cnt),
            "top_ports":      top_pts,
            "ip_entropy":     self._entropy(list(ip_cnt.values())),
            "port_scan_ips":  port_scan_ips,
            "brute_ips":      brute_ips,
            "crit_hits":      crit,
            "top_src_count":  ip_cnt.most_common(1)[0][1] if ip_cnt else 0,
        }

    def _entropy(self, counts: List[int]) -> float:
        t = sum(counts)
        return 0.0 if not t else -sum((c/t)*math.log2(c/t) for c in counts if c)

    def _empty(self) -> Dict:
        return {k: 0 for k in [
            "total", "blocked", "allowed", "block_rate",
            "unique_src", "ip_entropy", "crit_hits", "top_src_count"
        ]} | {"top_ports": [], "port_scan_ips": [], "brute_ips": []}

# ── ML ANOMALY DETECTOR ────────────────────────────────────────────────────────
class AnomalyDetector:
    """Isolation Forest — trains on historical windows."""

    def __init__(self):
        self.model   = IsolationForest(contamination=0.1, random_state=42) if ML_OK else None
        self.history = []
        self.trained = False

    def _vec(self, f: Dict) -> List[float]:
        return [
            f.get("total", 0),
            f.get("block_rate", 0),
            f.get("unique_src", 0),
            f.get("ip_entropy", 0),
            f.get("crit_hits", 0),
            f.get("top_src_count", 0),
            len(f.get("port_scan_ips", [])),
            len(f.get("brute_ips", [])),
        ]

    def score(self, feats: Dict) -> float:
        if not ML_OK:
            return self._heuristic(feats)
        v = self._vec(feats)
        self.history.append(v)
        if len(self.history) < 20:
            return self._heuristic(feats)
        if not self.trained or len(self.history) % 10 == 0:
            self.model.fit(self.history[-200:])
            self.trained = True
        raw = self.model.score_samples([v])[0]
        return round(max(0, min(10, (-raw - 0.3) * 20)), 2)

    def _heuristic(self, f: Dict) -> float:
        s = 0.0
        if f.get("block_rate", 0)  > 0.7: s += 3
        if f.get("unique_src", 0)  > 100:  s += 2
        if f.get("ip_entropy", 0)  > 5:    s += 2
        if f.get("port_scan_ips"):          s += 2
        if f.get("brute_ips"):              s += 1
        return min(10.0, s)

# ── RISK SCORER ────────────────────────────────────────────────────────────────
class RiskScorer:
    """
    Weighted risk formula:
      Risk = (EL×0.25 + AS×0.20 + AC×0.25 + RV×0.20 + TA×0.10) × 10

    EL = Exploit Likelihood
    AS = Attack Surface
    AC = Asset Criticality
    RV = Rule Violation
    TA = Traffic Anomaly (ML)
    """

    WEIGHTS = {"EL": 0.25, "AS": 0.20, "AC": 0.25, "RV": 0.20, "TA": 0.10}

    def __init__(self, anomaly: AnomalyDetector):
        self.anomaly = anomaly

    def score(self, f: Dict) -> Dict:
        EL = min(10, f.get("block_rate", 0) * 5 +
                 sum(1 for p in f.get("top_ports", [])
                     if p in {22, 23, 3389, 445, 1433, 3306, 5432}))
        AS = min(10,
                 min(5, f.get("unique_src", 0) / 20) +
                 min(5, len(f.get("top_ports", [])) / 2))
        AC = min(10, f.get("crit_hits", 0) / max(1, f.get("total", 1)) * 20)
        RV = min(10,
                 len(f.get("port_scan_ips", [])) * 3 +
                 len(f.get("brute_ips", [])) * 2)
        TA = self.anomaly.score(f)

        raw  = (self.WEIGHTS["EL"] * EL + self.WEIGHTS["AS"] * AS +
                self.WEIGHTS["AC"] * AC + self.WEIGHTS["RV"] * RV +
                self.WEIGHTS["TA"] * TA)
        risk = round(raw * 10, 1)
        sev  = ("CRITICAL" if risk >= 90 else
                "HIGH"     if risk >= 70 else
                "MEDIUM"   if risk >= 40 else "LOW")

        return {
            "exploit_likelihood": round(EL, 2),
            "attack_surface":     round(AS, 2),
            "asset_criticality":  round(AC, 2),
            "rule_violation":     round(RV, 2),
            "traffic_anomaly":    round(TA, 2),
            "risk_score":         risk,
            "severity":           sev,
        }

# ── LLM REMEDIATION ────────────────────────────────────────────────────────────
class LLMEngine:
    """Claude API — explains risk and suggests pfSense fix commands."""

    def analyze(self, f: Dict, s: Dict) -> Tuple[str, str]:
        if (not LLM_OK or not config["anthropic_key"] or
                s["severity"] not in ("HIGH", "CRITICAL")):
            return self._fallback_exp(s), self._fallback_fix(f)
        try:
            client = anthropic.Anthropic(api_key=config["anthropic_key"])
            prompt = (
                f"pfSense firewall: risk={s['risk_score']}/100 ({s['severity']}), "
                f"events={f['total']}, blocked={f['blocked']}, "
                f"port_scans={[x['ip'] for x in f.get('port_scan_ips',[])[:3]]}, "
                f"brute_force={[x['ip'] for x in f.get('brute_ips',[])[:3]]}, "
                f"top_ports={f.get('top_ports',[])[:5]}. "
                f"Respond ONLY in JSON (no markdown): "
                f'{{"explanation":"2 sentences","fix":"pfctl command"}}'
            )
            resp = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=300,
                messages=[{"role": "user", "content": prompt}],
            )
            data = json.loads(resp.content[0].text.strip())
            return data.get("explanation", ""), data.get("fix", "")
        except Exception as e:
            log.error(f"LLM error: {e}")
            return self._fallback_exp(s), self._fallback_fix(f)

    def _fallback_exp(self, s: Dict) -> str:
        return (
            f"Risk score is {s['risk_score']}/100 with severity {s['severity']}. "
            f"Exploit likelihood={s['exploit_likelihood']}/10, "
            f"Traffic anomaly={s['traffic_anomaly']}/10."
        )

    def _fallback_fix(self, f: Dict) -> str:
        ips = [x["ip"] for x in
               (f.get("port_scan_ips", []) + f.get("brute_ips", []))[:5]]
        if ips:
            return "\n".join(f"pfctl -t blocklist -T add {ip}" for ip in ips)
        return "pfctl -t blocklist -T add <suspicious_ip>"

# ── REPORT STORE ───────────────────────────────────────────────────────────────
class Store:
    """In-memory store for risk reports (last 24h = 288 windows)."""

    def __init__(self):
        self.reports: List[RiskReport] = []
        self._lock = threading.Lock()

    def add(self, r: RiskReport):
        with self._lock:
            self.reports.append(r)
            if len(self.reports) > 288:
                self.reports.pop(0)

    def latest(self) -> Optional[RiskReport]:
        with self._lock:
            return self.reports[-1] if self.reports else None

    def history(self, n: int = 24) -> List[RiskReport]:
        with self._lock:
            return self.reports[-n:]

# ── ORCHESTRATOR ───────────────────────────────────────────────────────────────
collector = Collector()
parser    = Parser()
extractor = FeatureExtractor()
anomaly   = AnomalyDetector()
scorer    = RiskScorer(anomaly)
llm       = LLMEngine()
store     = Store()

def build_threats(f: Dict) -> List[dict]:
    out, seen = [], set()
    for e in f.get("port_scan_ips", []):
        seen.add(e["ip"])
        out.append({
            "ip":          e["ip"],
            "attack_type": "Port Scan",
            "attempts":    len(e["ports"]),
            "ports":       e["ports"][:8],
            "last_seen":   datetime.now().strftime("%H:%M:%S"),
            "risk_level":  "HIGH",
        })
    for e in f.get("brute_ips", []):
        if e["ip"] not in seen:
            seen.add(e["ip"])
            out.append({
                "ip":          e["ip"],
                "attack_type": "Brute Force",
                "attempts":    e["attempts"],
                "ports":       [22, 3389],
                "last_seen":   datetime.now().strftime("%H:%M:%S"),
                "risk_level":  "CRITICAL" if e["attempts"] > 100 else "HIGH",
            })
    return out

def run_cycle() -> RiskReport:
    log.info("── collection cycle ──────────────────────")
    lines   = collector.collect()
    events  = parser.parse(lines)
    feats   = extractor.extract(events)
    scores  = scorer.score(feats)
    exp, fix = llm.analyze(feats, scores)
    threats = build_threats(feats)

    report = RiskReport(
        timestamp          = datetime.now().isoformat(),
        window_min         = config["interval_min"],
        total              = feats["total"],
        blocked            = feats["blocked"],
        allowed            = feats["allowed"],
        unique_src         = feats["unique_src"],
        top_ports          = feats["top_ports"][:10],
        exploit_likelihood = scores["exploit_likelihood"],
        attack_surface     = scores["attack_surface"],
        asset_criticality  = scores["asset_criticality"],
        rule_violation     = scores["rule_violation"],
        traffic_anomaly    = scores["traffic_anomaly"],
        risk_score         = scores["risk_score"],
        severity           = scores["severity"],
        threats            = threats,
        llm_explanation    = exp,
        llm_fix            = fix,
    )
    store.add(report)
    log.info(f"Risk={report.risk_score}/100 [{report.severity}] "
             f"Events={report.total} Threats={len(threats)}")
    return report

# ── FLASK APP ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# ── REST API ENDPOINTS ─────────────────────────────────────────────────────────
@app.route("/api/overview")
def api_overview():
    r = store.latest()
    if not r:
        return jsonify({"error": "no data yet"})
    return jsonify({
        "timestamp":  r.timestamp,
        "risk_score": r.risk_score,
        "severity":   r.severity,
        "total":      r.total,
        "blocked":    r.blocked,
        "allowed":    r.allowed,
        "unique_src": r.unique_src,
        "window_min": r.window_min,
        "top_ports":  r.top_ports,
    })

@app.route("/api/factors")
def api_factors():
    r = store.latest()
    if not r:
        return jsonify({})
    return jsonify({
        "exploit_likelihood": r.exploit_likelihood,
        "attack_surface":     r.attack_surface,
        "asset_criticality":  r.asset_criticality,
        "rule_violation":     r.rule_violation,
        "traffic_anomaly":    r.traffic_anomaly,
    })

@app.route("/api/threats")
def api_threats():
    r = store.latest()
    return jsonify(r.threats if r else [])

@app.route("/api/history")
def api_history():
    n = int(request.args.get("n", 24))
    return jsonify([{
        "timestamp":  r.timestamp,
        "risk_score": r.risk_score,
        "severity":   r.severity,
        "total":      r.total,
        "blocked":    r.blocked,
    } for r in store.history(n)])

@app.route("/api/ai-fix")
def api_ai_fix():
    r = store.latest()
    if not r:
        return jsonify({"explanation": "No data yet", "fix": ""})
    return jsonify({
        "explanation": r.llm_explanation,
        "fix":         r.llm_fix,
    })

@app.route("/api/block-ip", methods=["POST"])
def api_block():
    ip = request.get_json().get("ip", "").strip()
    if not ip:
        return jsonify({"success": False, "message": "No IP provided"}), 400
    ok, msg = collector.block_ip(ip)
    return jsonify({"success": ok, "message": msg})

@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "GET":
        safe = {k: v for k, v in config.items() if k != "anthropic_key"}
        safe["has_api_key"] = bool(config["anthropic_key"])
        return jsonify(safe)
    for k, v in request.get_json().items():
        if k in config:
            config[k] = v
    return jsonify({"success": True, "message": "Settings saved ✓"})

@app.route("/api/trigger", methods=["POST"])
def api_trigger():
    return jsonify(asdict(run_cycle()))

@app.route("/api/status")
def api_status():
    return jsonify({
        "ssh":       SSH_OK,
        "ml":        ML_OK,
        "llm":       LLM_OK and bool(config["anthropic_key"]),
        "demo_mode": config["demo_mode"],
        "fw_host":   config["fw_host"],
        "reports":   len(store.reports),
    })

@app.route("/api/test-ssh")
def api_test_ssh():
    if not SSH_OK:
        return jsonify({"success": False, "message": "Install paramiko: pip install paramiko"})
    if config["demo_mode"]:
        return jsonify({"success": False, "message": "Demo mode is ON — disable in Settings"})
    try:
        import paramiko as pm
        c = pm.SSHClient()
        c.set_missing_host_key_policy(pm.AutoAddPolicy())
        c.connect(
            hostname=config["fw_host"],
            port=int(config["fw_port"]),
            username=config["fw_user"],
            password=config["fw_password"],
            timeout=15,
            look_for_keys=False,
        )
        _, o, _ = c.exec_command(
            "clog /var/log/filter.log 2>/dev/null | tail -n 5 || echo NO_LOGS"
        )
        out   = o.read().decode(errors="ignore").strip()
        lines = [l for l in out.splitlines() if l.strip()]
        c.close()
        return jsonify({
            "success":        True,
            "message":        f"Connected to pfSense {config['fw_host']}",
            "lines_received": len(lines),
            "sample":         lines[-1] if lines else "No logs yet",
        })
    except pm.AuthenticationException:
        return jsonify({"success": False, "message": "Wrong username or password"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

# ── SERVE FRONTEND ─────────────────────────────────────────────────────────────
@app.route("/")
def index():
    try:
        with open("../frontend/index.html", "r") as f:
            return Response(f.read(), mimetype="text/html")
    except FileNotFoundError:
        return Response(FALLBACK_HTML, mimetype="text/html")

FALLBACK_HTML = """<!DOCTYPE html>
<html><head><title>pfSense Monitor</title>
<style>body{font-family:system-ui;background:#0f1117;color:#e2e8f0;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{text-align:center;padding:40px;background:#161b27;border-radius:12px}
a{color:#a78bfa;text-decoration:none;font-size:14px;display:block;margin:8px 0}
</style></head><body>
<div class="box">
  <h2 style="color:#a78bfa;margin-bottom:16px">pfSense Risk Monitor API</h2>
  <p style="color:#64748b;margin-bottom:20px">Backend is running. Open frontend/index.html in browser.</p>
  <a href="/api/overview">/api/overview</a>
  <a href="/api/factors">/api/factors</a>
  <a href="/api/threats">/api/threats</a>
  <a href="/api/history">/api/history</a>
  <a href="/api/ai-fix">/api/ai-fix</a>
  <a href="/api/status">/api/status</a>
  <a href="/api/test-ssh">/api/test-ssh</a>
</div></body></html>"""

# ── SCHEDULER ──────────────────────────────────────────────────────────────────
def start_scheduler():
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        s = BackgroundScheduler()
        s.add_job(run_cycle, "interval", minutes=config["interval_min"])
        s.start()
        log.info(f"Scheduler: every {config['interval_min']} minutes")
    except ImportError:
        log.warning("APScheduler not installed — run: pip install apscheduler")

# ── ENTRY POINT ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*50)
    print("  Intelligent pfSense Firewall Monitor")
    print("  Backend:   http://localhost:5000")
    print("  Dashboard: http://localhost:5000")
    print("  Test SSH:  http://localhost:5000/api/test-ssh")
    print("="*50 + "\n")
    run_cycle()
    start_scheduler()
    app.run(debug=False, port=5000, use_reloader=False)
