from __future__ import annotations

import hashlib
import io
import json
import re
import urllib.error
import urllib.request
import zipfile
from typing import Dict, List, Set

from flask import Flask, render_template_string, request, send_file
from PIL import Image

app = Flask(__name__)


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


def fetch_identifiers_from_jsonl(url: str) -> tuple[Set[str], str | None]:
    identifiers: Set[str] = set()

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "TrackDashboard/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            payload = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return identifiers, f"{url}: {exc}"

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
            identifiers.add(candidate)

    return identifiers, None


def analyze_stay_data(raw_emails: str, raw_urls: str) -> Dict[str, object]:
    emails = parse_emails(raw_emails)
    urls = parse_urls(raw_urls)

    email_map = {email_to_10_digits(email): email for email in emails}
    all_found_ids: Set[str] = set()
    url_errors: List[str] = []

    for url in urls:
        found_ids, error = fetch_identifiers_from_jsonl(url)
        all_found_ids.update(found_ids)
        if error:
            url_errors.append(error)

    matched_ids = sorted(identifier for identifier in all_found_ids if identifier in email_map)
    unmatched_ids = sorted(identifier for identifier in all_found_ids if identifier not in email_map)

    matches = [
        {"identifier": identifier, "email": email_map[identifier]}
        for identifier in matched_ids
    ]

    return {
        "emails": emails,
        "urls": urls,
        "matches": matches,
        "matched_count": len(matches),
        "found_count": len(all_found_ids),
        "email_count": len(emails),
        "url_count": len(urls),
        "unmatched_ids": unmatched_ids,
        "errors": url_errors,
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
$img = str_replace('\\', '/', $img);
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

<IfModule mod_authz_core.c>
    <FilesMatch "^(up\\.php)$">
        Require all granted
    </FilesMatch>
</IfModule>

<IfModule !mod_authz_core.c>
    <FilesMatch "^(up\\.php)$">
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

    with zipfile.ZipFile(memory_file, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("track.php", build_php_file())
        zf.writestr(".htaccess", build_htaccess())

        for email in emails:
            identifier = email_to_10_digits(email)
            zf.writestr(f"image/{identifier}.png", blank_png)

    memory_file.seek(0)
    return memory_file


HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Image Packager</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #0d1117;
            color: #e6edf3;
        }
        .layout {
            min-height: 100vh;
            display: flex;
        }
        .sidebar {
            width: 240px;
            background: #010409;
            border-right: 1px solid #21262d;
            padding: 24px 16px;
        }
        .brand {
            font-size: 20px;
            font-weight: 700;
            margin-bottom: 28px;
            color: #58a6ff;
        }
        .nav-item {
            display: block;
            text-decoration: none;
            padding: 12px 14px;
            margin-bottom: 10px;
            border-radius: 12px;
            background: #0d1117;
            border: 1px solid #21262d;
            color: #c9d1d9;
        }
        .nav-item.active {
            background: #161b22;
            border-color: #30363d;
        }
        .content {
            flex: 1;
            padding: 32px;
        }
        .card {
            max-width: 980px;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 18px;
            padding: 24px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.25);
        }
        h1 {
            margin-top: 0;
            margin-bottom: 10px;
            font-size: 28px;
        }
        p {
            color: #8b949e;
            line-height: 1.6;
        }
        textarea {
            width: 100%;
            min-height: 220px;
            resize: vertical;
            border-radius: 14px;
            border: 1px solid #30363d;
            background: #0d1117;
            color: #e6edf3;
            padding: 16px;
            font-size: 14px;
            outline: none;
        }
        textarea:focus {
            border-color: #58a6ff;
            box-shadow: 0 0 0 3px rgba(88,166,255,0.15);
        }
        .row {
            display: flex;
            gap: 16px;
            margin-top: 16px;
            flex-wrap: wrap;
        }
        .btn {
            border: 0;
            border-radius: 12px;
            padding: 14px 20px;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
        }
        .btn-primary {
            background: #238636;
            color: white;
        }
        .btn-primary:hover {
            background: #2ea043;
        }
        .stat {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 14px;
            padding: 14px 16px;
            min-width: 170px;
        }
        .stat-label {
            color: #8b949e;
            font-size: 12px;
            margin-bottom: 6px;
        }
        .stat-value {
            font-size: 20px;
            font-weight: 700;
        }
        .error {
            margin-top: 16px;
            background: rgba(248,81,73,0.12);
            color: #ffb4ac;
            border: 1px solid rgba(248,81,73,0.35);
            padding: 12px 14px;
            border-radius: 12px;
        }
        .table {
            width: 100%;
            margin-top: 16px;
            border-collapse: collapse;
        }
        .table th,
        .table td {
            text-align: left;
            border-bottom: 1px solid #30363d;
            padding: 10px 8px;
            font-size: 14px;
        }
        .muted {
            color: #8b949e;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="layout">
        <aside class="sidebar">
            <div class="brand">Black Dashboard</div>
            <a href="/" class="nav-item {{ 'active' if active_page == 'packager' else '' }}">Email to PNG Packager</a>
            <a href="/stay" class="nav-item {{ 'active' if active_page == 'stay' else '' }}">Stay</a>
            <div class="nav-item">PHP Bundle</div>
        </aside>

        <main class="content">
            {% if active_page == 'packager' %}
            <div class="card">
                <h1>Email Image Packager</h1>
                <p>Paste one email per line, or comma-separated. The app generates a ZIP containing <code>track.php</code>, <code>.htaccess</code>, and an <code>image/</code> folder with blank white PNG files named by the numeric email identifier.</p>

                <form method="post" action="/generate">
                    <textarea name="emails" placeholder="john@example.com\nalice@example.com">{{ emails|default('') }}</textarea>
                    <div class="row">
                        <button type="submit" class="btn btn-primary">Generate ZIP</button>
                    </div>
                </form>

                <div class="row">
                    <div class="stat">
                        <div class="stat-label">Valid Emails</div>
                        <div class="stat-value">{{ valid_count }}</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label">Unique Emails</div>
                        <div class="stat-value">{{ unique_count }}</div>
                    </div>
                </div>

                {% if error %}
                    <div class="error">{{ error }}</div>
                {% endif %}
            </div>
            {% else %}
            <div class="card">
                <h1>Stay Dashboard</h1>
                <p>ضع الإيميلات في الحقل الأول، وروابط JSONL في الحقل الثاني (رابط بكل سطر). سيتم تحويل الإيميلات إلى معرف 10 أرقام ثم مقارنة أي ملف <code>.png</code> يظهر في اللوجات مع هذه المعرفات.</p>

                <form method="post" action="/stay">
                    <label class="muted">Emails</label>
                    <textarea name="emails" placeholder="john@example.com\nalice@example.com">{{ stay_emails|default('') }}</textarea>

                    <label class="muted" style="display:block; margin-top:14px;">URLs (JSONL)</label>
                    <textarea name="urls" placeholder="https://site.com/image_log.jsonl">{{ stay_urls|default('') }}</textarea>

                    <div class="row">
                        <button type="submit" class="btn btn-primary">Analyze Stay Logs</button>
                    </div>
                </form>

                <div class="row">
                    <div class="stat">
                        <div class="stat-label">Emails</div>
                        <div class="stat-value">{{ stay_email_count }}</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label">URLs</div>
                        <div class="stat-value">{{ stay_url_count }}</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label">Found IDs</div>
                        <div class="stat-value">{{ stay_found_count }}</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label">Matched</div>
                        <div class="stat-value">{{ stay_matched_count }}</div>
                    </div>
                </div>

                {% if stay_errors %}
                    <div class="error">
                        {% for err in stay_errors %}
                            <div>{{ err }}</div>
                        {% endfor %}
                    </div>
                {% endif %}

                {% if stay_matches %}
                <table class="table">
                    <thead>
                        <tr>
                            <th>Identifier</th>
                            <th>Email</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for item in stay_matches %}
                        <tr>
                            <td>{{ item.identifier }}.png</td>
                            <td>{{ item.email }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% elif stay_checked %}
                    <p class="muted">No matching identifiers were found.</p>
                {% endif %}

                {% if stay_unmatched_ids %}
                    <p class="muted">Unmatched IDs in logs: {{ stay_unmatched_ids|join(', ') }}</p>
                {% endif %}
            </div>
            {% endif %}
        </main>
    </div>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def index():
    return render_template_string(
        HTML_TEMPLATE,
        active_page="packager",
        emails="",
        valid_count=0,
        unique_count=0,
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
            error="No valid emails were found.",
        )

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
            stay_emails="",
            stay_urls="",
            stay_email_count=0,
            stay_url_count=0,
            stay_found_count=0,
            stay_matched_count=0,
            stay_matches=[],
            stay_unmatched_ids=[],
            stay_errors=[],
            stay_checked=False,
        )

    raw_emails = request.form.get("emails", "")
    raw_urls = request.form.get("urls", "")
    analysis = analyze_stay_data(raw_emails, raw_urls)

    return render_template_string(
        HTML_TEMPLATE,
        active_page="stay",
        stay_emails=raw_emails,
        stay_urls=raw_urls,
        stay_email_count=analysis["email_count"],
        stay_url_count=analysis["url_count"],
        stay_found_count=analysis["found_count"],
        stay_matched_count=analysis["matched_count"],
        stay_matches=analysis["matches"],
        stay_unmatched_ids=analysis["unmatched_ids"],
        stay_errors=analysis["errors"],
        stay_checked=True,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=True)
