from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Set, Tuple

from flask import Flask, jsonify, render_template_string, request, send_file
from PIL import Image

app = Flask(__name__)
DB_PATH = Path(__file__).with_name("tracker.db")
IPDETECTIVE_API_URL = "https://api.ipdetective.io/ip"
DEFAULT_IPDETECTIVE_API_KEY = "050ee9d4-f74e-4eb6-b266-f8fec46855da"
IPDETECTIVE_API_KEY = os.getenv("IPDETECTIVE_API_KEY", DEFAULT_IPDETECTIVE_API_KEY)
BOT_IP_CACHE: Dict[str, bool] = {}


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS email_mappings (
                email TEXT PRIMARY KEY,
                identifier TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_generated_at TEXT NOT NULL
            )
            """
        )


def upsert_email_mappings(emails: List[str]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    rows = [(email, email_to_10_digits(email), now, now) for email in emails]

    with sqlite3.connect(DB_PATH) as conn:
        conn.executemany(
            """
            INSERT INTO email_mappings (email, identifier, created_at, last_generated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                identifier=excluded.identifier,
                last_generated_at=excluded.last_generated_at
            """,
            rows,
        )


def get_all_email_mappings() -> List[Dict[str, str]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT email, identifier, created_at, last_generated_at
            FROM email_mappings
            ORDER BY last_generated_at DESC
            """
        ).fetchall()

    return [dict(row) for row in rows]


def email_to_10_digits(email: str) -> str:
    normalized = email.strip().lower()
    digest = hashlib.sha256(normalized.encode("utf-8")).digest()
    num = int.from_bytes(digest[:8], "big") % 10_000_000_000
    return str(num).zfill(10)


def parse_emails(raw: str) -> List[str]:
    candidates = [line.strip() for line in raw.replace(",", "\n").splitlines()]
    email_regex = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

    seen = set()
    results: List[str] = []

    for item in candidates:
        if not item:
            continue
        normalized = item.lower()
        if not email_regex.match(normalized):
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        results.append(normalized)

    return results


def parse_urls(raw: str) -> List[str]:
    candidates = [line.strip() for line in raw.replace(",", "\n").splitlines()]
    seen: Set[str] = set()
    urls: List[str] = []

    for item in candidates:
        if not item:
            continue
        if not item.lower().startswith(("http://", "https://")):
            continue
        if item in seen:
            continue
        seen.add(item)
        urls.append(item)

    return urls


def extract_identifier_from_text(value: str) -> str | None:
    match = re.search(r"(\d{10})\.png", value)
    if match:
        return match.group(1)
    return None


def normalize_jsonl_url(url: str) -> str:
    cleaned = url.strip()
    if cleaned.endswith("/image_log.jsonl"):
        return cleaned
    return cleaned.rstrip("/") + "/image_log.jsonl"


def fetch_records_from_jsonl(url: str) -> Tuple[List[Dict[str, object]], str | None]:
    records: List[Dict[str, object]] = []
    target_url = normalize_jsonl_url(url)

    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": "TrackDashboard/2.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            payload = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return records, f"{target_url}: {exc}"

    for line in payload.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            continue

        image_value = str(record.get("image", ""))
        request_uri = str(record.get("request_uri", ""))

        candidate = extract_identifier_from_text(image_value) or extract_identifier_from_text(request_uri)
        if candidate:
            record["identifier"] = candidate
            record["source_url"] = target_url
            record["event_key"] = (
                f"{target_url}|{record.get('timestamp', '')}|{record.get('image', '')}|{record.get('ip', '')}"
            )
            records.append(record)

    return records, None


def is_bot_ip(ip_value: str) -> bool:
    ip = ip_value.strip()
    if not ip or ip.lower() == "unknown":
        return False

    if ip in BOT_IP_CACHE:
        return BOT_IP_CACHE[ip]

    req = urllib.request.Request(
        f"{IPDETECTIVE_API_URL}?ip={urllib.parse.quote(ip)}",
        headers={
            "User-Agent": "TrackDashboard/2.0",
            "x-api-key": IPDETECTIVE_API_KEY,
        },
    )

    is_bot = False
    try:
        with urllib.request.urlopen(req, timeout=6) as response:
            payload = response.read().decode("utf-8", errors="replace")
            parsed = json.loads(payload)
            is_bot = bool(parsed.get("bot", False))
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError):
        is_bot = False

    BOT_IP_CACHE[ip] = is_bot
    return is_bot


def analyze_stay_data(raw_urls: str, known_event_keys: Set[str] | None = None) -> Dict[str, object]:
    urls = parse_urls(raw_urls)
    mapping_rows = get_all_email_mappings()
    email_map = {row["identifier"]: row["email"] for row in mapping_rows}

    known_event_keys = known_event_keys or set()
    all_found_ids: Set[str] = set()
    all_rows: List[Dict[str, object]] = []
    matched_rows: List[Dict[str, object]] = []
    new_matched_rows: List[Dict[str, object]] = []
    url_errors: List[str] = []

    for url in urls:
        records, error = fetch_records_from_jsonl(url)

        for record in records:
            identifier = str(record.get("identifier", ""))
            if not identifier:
                continue
            all_found_ids.add(identifier)

            enriched = {
                "email": email_map.get(identifier, ""),
                **record,
            }
            all_rows.append(enriched)

            if identifier in email_map:
                if not is_bot_ip(str(record.get("ip", ""))):
                    matched_rows.append(enriched)
                    if str(record.get("event_key", "")) not in known_event_keys:
                        new_matched_rows.append(enriched)

        if error:
            url_errors.append(error)

    def ts_sort_key(item: Dict[str, object]) -> int:
        value = item.get("timestamp")
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
        return 0

    matched_rows.sort(key=ts_sort_key, reverse=True)
    new_matched_rows.sort(key=ts_sort_key, reverse=True)
    all_rows.sort(key=ts_sort_key, reverse=True)

    unmatched_ids = sorted(identifier for identifier in all_found_ids if identifier not in email_map)

    return {
        "urls": urls,
        "matches": matched_rows,
        "new_matches": new_matched_rows,
        "all_rows": all_rows[:120],
        "matched_count": len(matched_rows),
        "new_matched_count": len(new_matched_rows),
        "found_count": len(all_found_ids),
        "stored_email_count": len(mapping_rows),
        "url_count": len(urls),
        "unmatched_ids": unmatched_ids,
        "errors": url_errors,
        "stored_mappings": mapping_rows[:120],
        "run_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def build_php_file() -> str:
    return """<?php
declare(strict_types=1);

$baseDir = __DIR__ . '/image/';
$logFile = __DIR__ . '/image_log.jsonl';

function getClientIp(): string
{
    $keys = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'REMOTE_ADDR',
    ];

    foreach ($keys as $key) {
        if (!empty($_SERVER[$key])) {
            $value = trim((string) $_SERVER[$key]);

            if ($key === 'HTTP_X_FORWARDED_FOR') {
                $parts = explode(',', $value);
                $value = trim($parts[0]);
            }

            if (filter_var($value, FILTER_VALIDATE_IP)) {
                return $value;
            }
        }
    }

    return 'unknown';
}

function getServerValue(string $key, string $default = ''): string
{
    return isset($_SERVER[$key]) ? trim((string) $_SERVER[$key]) : $default;
}

$img = $_GET['img'] ?? '';
$img = str_replace('\\\\', '/', $img);
$img = ltrim($img, '/');

if ($img === '' || !preg_match('/^[A-Za-z0-9._-]+\.png$/i', $img)) {
    http_response_code(400);
    exit('Invalid image name');
}

$imagePath = realpath($baseDir . $img);
$baseReal  = realpath($baseDir);

if ($imagePath === false || $baseReal === false || strpos($imagePath, $baseReal) !== 0 || !is_file($imagePath)) {
    http_response_code(404);
    exit('Image not found');
}

$ip        = getClientIp();
$userAgent = getServerValue('HTTP_USER_AGENT', 'unknown');
$referer   = getServerValue('HTTP_REFERER', 'direct');
$method    = getServerValue('REQUEST_METHOD', 'GET');
$requestUri = getServerValue('REQUEST_URI', '');
$timeIso   = date('c');
$timestamp = time();

$record = [
    'time_iso'    => $timeIso,
    'timestamp'   => $timestamp,
    'image'       => $img,
    'ip'          => $ip,
    'user_agent'  => $userAgent,
    'referer'     => $referer,
    'method'      => $method,
    'request_uri' => $requestUri,
];

file_put_contents(
    $logFile,
    json_encode($record, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL,
    FILE_APPEND | LOCK_EX
);

header('Content-Type: image/png');
header('Content-Length: ' . (string) filesize($imagePath));
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

readfile($imagePath);
exit;
"""


def build_htaccess() -> str:
    return """Options -Indexes
DirectoryIndex disabled

<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^image/([A-Za-z0-9._-]+\.png)$ track.php?img=$1 [L,QSA,NC]
</IfModule>

<IfModule mod_authz_core.c>
    <FilesMatch "^(track\\.php|image_log\\.jsonl)$">
        Require all granted
    </FilesMatch>

    <FilesMatch "\\.png$">
        Require all granted
    </FilesMatch>
</IfModule>

<IfModule !mod_authz_core.c>
    <FilesMatch "^(track\\.php|image_log\\.jsonl)$">
        Order Allow,Deny
        Allow from all
    </FilesMatch>

    <FilesMatch "\\.png$">
        Order Allow,Deny
        Allow from all
    </FilesMatch>
</IfModule>
"""


def make_blank_png_bytes(width: int = 1, height: int = 1) -> bytes:
    image = Image.new("RGB", (width, height), "white")
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return buf.getvalue()


def build_zip(emails: List[str]) -> io.BytesIO:
    memory_file = io.BytesIO()
    blank_png = make_blank_png_bytes()

    def write_with_mode(
        zf: zipfile.ZipFile,
        filename: str,
        data: bytes | str,
        mode: int,
        is_dir: bool = False,
    ) -> None:
        info = zipfile.ZipInfo(filename)
        info.date_time = datetime.now().timetuple()[:6]
        info.create_system = 3  # Unix
        file_type = 0o040000 if is_dir else 0o100000
        info.external_attr = ((file_type | mode) & 0xFFFF) << 16
        zf.writestr(info, data)

    with zipfile.ZipFile(memory_file, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        write_with_mode(zf, "track.php", build_php_file(), 0o644)
        write_with_mode(zf, ".htaccess", build_htaccess(), 0o644)
        write_with_mode(zf, "image/", b"", 0o755, is_dir=True)

        for email in emails:
            identifier = email_to_10_digits(email)
            write_with_mode(zf, f"image/{identifier}.png", blank_png, 0o644)

    memory_file.seek(0)
    return memory_file


HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Tracker Workbench</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Inter, Arial, sans-serif;
            background: radial-gradient(circle at top right, #1b2a4a, #0c111b 45%);
            color: #edf2f8;
        }
        .layout { min-height: 100vh; display: flex; }
        .sidebar {
            width: 260px;
            background: rgba(8,12,19,0.95);
            border-right: 1px solid #273247;
            padding: 24px 16px;
            position: sticky;
            top: 0;
            height: 100vh;
        }
        .brand {
            font-size: 20px;
            font-weight: 800;
            color: #61dafb;
            margin-bottom: 8px;
        }
        .subtitle {
            color: #9cb0cc;
            font-size: 12px;
            margin-bottom: 22px;
        }
        .nav-item {
            display: block;
            text-decoration: none;
            padding: 12px 14px;
            margin-bottom: 10px;
            border-radius: 12px;
            background: #121b2a;
            border: 1px solid #2d3d5d;
            color: #d7e4fb;
            font-weight: 600;
        }
        .nav-item.active { background: #203050; border-color: #4f78d0; }
        .content { flex: 1; padding: 28px; }
        .card {
            width: 100%;
            background: rgba(14,20,32,0.95);
            border: 1px solid #2d3d5d;
            border-radius: 18px;
            padding: 24px;
            box-shadow: 0 16px 40px rgba(0,0,0,0.35);
            margin-bottom: 18px;
        }
        h1 { margin: 0 0 8px; font-size: 30px; }
        p { color: #acc0df; line-height: 1.6; }
        textarea {
            width: 100%; min-height: 180px; resize: vertical; border-radius: 14px;
            border: 1px solid #41557a; background: #0b1220; color: #edf2f8;
            padding: 14px; font-size: 14px; outline: none;
        }
        textarea:focus { border-color: #61dafb; box-shadow: 0 0 0 3px rgba(97,218,251,0.2); }
        .row { display: flex; gap: 12px; margin-top: 14px; flex-wrap: wrap; align-items: center; }
        .btn {
            border: 0; border-radius: 12px; padding: 12px 18px; font-size: 14px;
            font-weight: 700; cursor: pointer;
        }
        .btn-primary { background: linear-gradient(90deg, #2775ff, #32c5ff); color: white; }
        .btn-muted { background: #1f2a3f; color: #d7e4fb; border: 1px solid #40557d; }
        .pill {
            border: 1px solid #335a78; background: #112033; color: #9fd6f5;
            border-radius: 999px; padding: 6px 10px; font-size: 12px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 12px;
            margin-top: 16px;
        }
        .stat {
            background: #0c1526;
            border: 1px solid #2f4468;
            border-radius: 14px;
            padding: 12px;
        }
        .stat-label { color: #95accf; font-size: 12px; margin-bottom: 4px; }
        .stat-value { font-size: 22px; font-weight: 800; }
        .error {
            margin-top: 16px; background: rgba(248,81,73,0.13); color: #ffcbc6;
            border: 1px solid rgba(248,81,73,0.35); padding: 12px 14px; border-radius: 12px;
        }
        .table-wrap { overflow-x: auto; border: 1px solid #2f4468; border-radius: 12px; margin-top: 14px; }
        .table { width: 100%; border-collapse: collapse; min-width: 840px; }
        .table th, .table td { text-align: left; border-bottom: 1px solid #263855; padding: 9px 8px; font-size: 13px; }
        .table th { color: #a8c3eb; background: #101d33; position: sticky; top: 0; }
        .muted { color: #97adcb; font-size: 13px; }
        .step-item { border-left: 3px solid #4fa4ff; padding: 8px 12px; margin-top: 8px; background: #101b2e; border-radius: 8px; }
        code { background: #0e1a2e; border: 1px solid #2f4468; padding: 2px 6px; border-radius: 7px; }
    </style>
</head>
<body>
    <div class="layout">
        <aside class="sidebar">
            <div class="brand">Tracker Workbench</div>
            <div class="subtitle">Generate, store, and monitor image tracking logs</div>
            <a href="/" class="nav-item {{ 'active' if active_page == 'packager' else '' }}">Email → PNG Package</a>
            <a href="/stay" class="nav-item {{ 'active' if active_page == 'stay' else '' }}">Stay Monitor</a>
        </aside>

        <main class="content">
            {% if active_page == 'packager' %}
            <div class="card">
                <h1>Email to PNG Package</h1>
                <p>Enter one email per line (or comma-separated). When you generate the ZIP, every email is automatically saved in the local database with its 10-digit identifier so the Stay Monitor can analyze logs using URLs only.</p>

                <form method="post" action="/generate">
                    <textarea name="emails" placeholder="john@example.com\nalice@example.com">{{ emails|default('') }}</textarea>
                    <div class="row">
                        <button type="submit" class="btn btn-primary">Generate ZIP + Save to DB</button>
                        <span class="pill">Database entries: {{ db_total }}</span>
                    </div>
                </form>

                <div class="stats-grid">
                    <div class="stat"><div class="stat-label">Valid Emails</div><div class="stat-value">{{ valid_count }}</div></div>
                    <div class="stat"><div class="stat-label">Unique Emails</div><div class="stat-value">{{ unique_count }}</div></div>
                    <div class="stat"><div class="stat-label">Stored IDs (DB)</div><div class="stat-value">{{ db_total }}</div></div>
                </div>

                {% if error %}<div class="error">{{ error }}</div>{% endif %}
            </div>
            {% else %}
            <div class="card">
                <h1>Stay Monitor Dashboard</h1>
                <p>Paste only JSONL URLs. The monitor uses saved email identifiers from the local database, analyzes logs immediately, and auto-polls every 30 seconds to surface new matches.</p>

                <form id="stay-form" method="post" action="/stay">
                    <label class="muted">URLs (one URL per line)</label>
                    <textarea id="urls" name="urls" placeholder="https://example.com/image_log.jsonl">{{ stay_urls|default('') }}</textarea>
                    <div class="row">
                        <button type="submit" class="btn btn-primary">Analyze Stay Logs</button>
                        <button id="toggle-monitor" type="button" class="btn btn-muted">Pause Auto Monitor</button>
                        <span class="pill">Poll interval: 30s</span>
                    </div>
                </form>

                <div class="stats-grid" id="stats-grid">
                    <div class="stat"><div class="stat-label">Stored Emails</div><div class="stat-value" id="stored-count">{{ stay_email_count }}</div></div>
                    <div class="stat"><div class="stat-label">URLs</div><div class="stat-value" id="url-count">{{ stay_url_count }}</div></div>
                    <div class="stat"><div class="stat-label">Found IDs</div><div class="stat-value" id="found-count">{{ stay_found_count }}</div></div>
                    <div class="stat"><div class="stat-label">Total Matched</div><div class="stat-value" id="matched-count">{{ stay_matched_count }}</div></div>
                    <div class="stat"><div class="stat-label">New Matches (last run)</div><div class="stat-value" id="new-count">0</div></div>
                </div>

                <div class="row muted" style="margin-top:14px;">
                    <span>Last run: <strong id="last-run">{{ stay_run_at or '-' }}</strong></span>
                    <span>Monitor status: <strong id="monitor-status">Active</strong></span>
                </div>

                <div id="error-box" class="error" style="display:none;"></div>

                <h3>Monitor Steps</h3>
                <div id="steps-log">
                    <div class="step-item">1) URLs accepted and normalized.</div>
                    <div class="step-item">2) image_log.jsonl records fetched from all URLs.</div>
                    <div class="step-item">3) Extracted 10-digit identifiers from image/request_uri fields.</div>
                    <div class="step-item">4) Compared identifiers with local DB mappings.</div>
                    <div class="step-item">5) Displayed complete and newly discovered matches.</div>
                </div>

                <h3 style="margin-top:20px;">Matched Events</h3>
                <div class="table-wrap">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Identifier</th><th>Email</th><th>Time ISO</th><th>Timestamp</th><th>Image</th><th>IP</th>
                                <th>User Agent</th><th>Referer</th><th>Method</th><th>Request URI</th><th>Source URL</th>
                            </tr>
                        </thead>
                        <tbody id="match-body">
                        {% for item in stay_matches %}
                        <tr>
                            <td>{{ item.identifier }}</td><td>{{ item.email }}</td><td>{{ item.time_iso }}</td><td>{{ item.timestamp }}</td>
                            <td>{{ item.image }}</td><td>{{ item.ip }}</td><td>{{ item.user_agent }}</td><td>{{ item.referer }}</td>
                            <td>{{ item.method }}</td><td>{{ item.request_uri }}</td><td>{{ item.source_url }}</td>
                        </tr>
                        {% endfor %}
                        </tbody>
                    </table>
                </div>

                <p class="muted" id="unmatched">{% if stay_unmatched_ids %}Unmatched IDs: {{ stay_unmatched_ids|join(', ') }}{% endif %}</p>

                <h3>Stored Mapping Snapshot</h3>
                <div class="table-wrap">
                    <table class="table">
                        <thead><tr><th>Email</th><th>Identifier</th><th>Created At</th><th>Last Generated</th></tr></thead>
                        <tbody id="mapping-body">
                        {% for row in stay_mappings %}
                        <tr><td>{{ row.email }}</td><td>{{ row.identifier }}</td><td>{{ row.created_at }}</td><td>{{ row.last_generated_at }}</td></tr>
                        {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>

            <script>
                const knownEventKeys = new Set();
                let monitorActive = true;

                function escapeHtml(value) {
                    return String(value ?? '').replace(/[&<>"']/g, function(ch) {
                        return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch];
                    });
                }

                function rowHtml(item) {
                    return `<tr>
                        <td>${escapeHtml(item.identifier)}</td><td>${escapeHtml(item.email)}</td><td>${escapeHtml(item.time_iso)}</td>
                        <td>${escapeHtml(item.timestamp)}</td><td>${escapeHtml(item.image)}</td><td>${escapeHtml(item.ip)}</td>
                        <td>${escapeHtml(item.user_agent)}</td><td>${escapeHtml(item.referer)}</td><td>${escapeHtml(item.method)}</td>
                        <td>${escapeHtml(item.request_uri)}</td><td>${escapeHtml(item.source_url)}</td>
                    </tr>`;
                }

                function renderAnalysis(data) {
                    document.getElementById('stored-count').textContent = data.stored_email_count;
                    document.getElementById('url-count').textContent = data.url_count;
                    document.getElementById('found-count').textContent = data.found_count;
                    document.getElementById('matched-count').textContent = data.matched_count;
                    document.getElementById('new-count').textContent = data.new_matched_count;
                    document.getElementById('last-run').textContent = data.run_at;
                    document.getElementById('unmatched').textContent = data.unmatched_ids.length
                        ? `Unmatched IDs: ${data.unmatched_ids.join(', ')}`
                        : 'All discovered IDs are mapped in the database.';

                    const body = document.getElementById('match-body');
                    body.innerHTML = data.matches.length ? data.matches.map(rowHtml).join('') : '<tr><td colspan="11">No matched events yet.</td></tr>';

                    const mappingBody = document.getElementById('mapping-body');
                    mappingBody.innerHTML = data.stored_mappings.length
                        ? data.stored_mappings.map(item => `<tr><td>${escapeHtml(item.email)}</td><td>${escapeHtml(item.identifier)}</td><td>${escapeHtml(item.created_at)}</td><td>${escapeHtml(item.last_generated_at)}</td></tr>`).join('')
                        : '<tr><td colspan="4">No saved mappings yet. Generate a package first.</td></tr>';

                    data.matches.forEach(item => {
                        if (item.event_key) {
                            knownEventKeys.add(item.event_key);
                        }
                    });

                    const errBox = document.getElementById('error-box');
                    if (data.errors.length) {
                        errBox.style.display = 'block';
                        errBox.innerHTML = data.errors.map(e => `<div>${escapeHtml(e)}</div>`).join('');
                    } else {
                        errBox.style.display = 'none';
                        errBox.innerHTML = '';
                    }
                }

                async function analyze() {
                    const urls = document.getElementById('urls').value;
                    const response = await fetch('/stay/analyze', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ urls, known_event_keys: Array.from(knownEventKeys) })
                    });
                    if (!response.ok) {
                        throw new Error('Analyze request failed');
                    }
                    const data = await response.json();
                    renderAnalysis(data);
                }

                document.getElementById('stay-form').addEventListener('submit', async function(event) {
                    event.preventDefault();
                    knownEventKeys.clear();
                    await analyze();
                });

                document.getElementById('toggle-monitor').addEventListener('click', function() {
                    monitorActive = !monitorActive;
                    document.getElementById('monitor-status').textContent = monitorActive ? 'Active' : 'Paused';
                    this.textContent = monitorActive ? 'Pause Auto Monitor' : 'Resume Auto Monitor';
                });

                setInterval(async () => {
                    if (!monitorActive) return;
                    if (!document.getElementById('urls').value.trim()) return;
                    try { await analyze(); } catch (err) { console.error(err); }
                }, 30000);
            </script>
            {% endif %}
        </main>
    </div>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def index():
    db_total = len(get_all_email_mappings())
    return render_template_string(
        HTML_TEMPLATE,
        active_page="packager",
        emails="",
        valid_count=0,
        unique_count=0,
        db_total=db_total,
        error="",
    )


@app.route("/generate", methods=["POST"])
def generate():
    raw_emails = request.form.get("emails", "")
    emails = parse_emails(raw_emails)

    if not emails:
        return render_template_string(
            HTML_TEMPLATE,
            active_page="packager",
            emails=raw_emails,
            valid_count=0,
            unique_count=0,
            db_total=len(get_all_email_mappings()),
            error="No valid emails were found.",
        )

    upsert_email_mappings(emails)
    zip_buffer = build_zip(emails)
    return send_file(
        zip_buffer,
        mimetype="application/zip",
        as_attachment=True,
        download_name="email_image_bundle.zip",
    )


@app.route("/stay", methods=["GET", "POST"])
def stay_dashboard():
    if request.method == "GET":
        return render_template_string(
            HTML_TEMPLATE,
            active_page="stay",
            stay_urls="",
            stay_email_count=len(get_all_email_mappings()),
            stay_url_count=0,
            stay_found_count=0,
            stay_matched_count=0,
            stay_matches=[],
            stay_unmatched_ids=[],
            stay_errors=[],
            stay_mappings=get_all_email_mappings()[:120],
            stay_run_at="-",
        )

    raw_urls = request.form.get("urls", "")
    analysis = analyze_stay_data(raw_urls)

    return render_template_string(
        HTML_TEMPLATE,
        active_page="stay",
        stay_urls=raw_urls,
        stay_email_count=analysis["stored_email_count"],
        stay_url_count=analysis["url_count"],
        stay_found_count=analysis["found_count"],
        stay_matched_count=analysis["matched_count"],
        stay_matches=analysis["matches"],
        stay_unmatched_ids=analysis["unmatched_ids"],
        stay_errors=analysis["errors"],
        stay_mappings=analysis["stored_mappings"],
        stay_run_at=analysis["run_at"],
    )


@app.route("/stay/analyze", methods=["POST"])
def stay_analyze_api():
    payload = request.get_json(silent=True) or {}
    raw_urls = str(payload.get("urls", ""))
    known_event_keys = {str(item) for item in payload.get("known_event_keys", []) if str(item).strip()}
    analysis = analyze_stay_data(raw_urls, known_event_keys=known_event_keys)
    return jsonify(analysis)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5004, debug=True)


init_db()
