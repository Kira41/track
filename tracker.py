from __future__ import annotations

import io
import os
import re
import zipfile
from pathlib import Path
from typing import List
import hashlib

from flask import Flask, render_template_string, request, send_file
from PIL import Image

app = Flask(__name__)


def email_to_10_digits(email: str) -> str:
    normalized = email.strip().lower()
    digest = hashlib.sha256(normalized.encode("utf-8")).digest()
    num = int.from_bytes(digest[:8], "big") % 10_000_000_000
    return str(num).zfill(10)

    if len(data) > 255:
        raise ValueError("Email too long")

    payload = bytes([len(data)]) + data
    num = int.from_bytes(payload, "big")
    return str(num)


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


def build_php_file() -> str:
    return """<?php

function decryptEmailNumeric(string $number): string
{
    if (!preg_match('/^\\d+$/', $number)) {
        throw new Exception("Invalid numeric input");
    }

    if (bccomp($number, '0') === 0) {
        throw new Exception("Invalid numeric payload");
    }

    $bytes = '';

    while (bccomp($number, '0') > 0) {
        $remainder = bcmod($number, '256');
        $bytes = chr((int)$remainder) . $bytes;
        $number = bcdiv($number, '256', '0');
    }

    if (strlen($bytes) < 1) {
        throw new Exception("Corrupted numeric payload");
    }

    $emailLen = ord($bytes[0]);
    $email = substr($bytes, 1, $emailLen);

    if (strlen($email) !== $emailLen) {
        throw new Exception("Corrupted numeric payload");
    }

    return $email;
}

header('Content-Type: text/plain; charset=utf-8');
echo "track.php generated successfully.";
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
            min-height: 320px;
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
    </style>
</head>
<body>
    <div class="layout">
        <aside class="sidebar">
            <div class="brand">Black Dashboard</div>
            <div class="nav-item active">Email to PNG Packager</div>
            <div class="nav-item">ZIP Export</div>
            <div class="nav-item">PHP Bundle</div>
        </aside>

        <main class="content">
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
        </main>
    </div>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def index():
    return render_template_string(
        HTML_TEMPLATE,
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=True)
