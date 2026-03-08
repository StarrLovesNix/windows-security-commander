"""
notifier.py - Windows toast notifications and HTML email reports.

Toast notifications use plyer (cross-platform) with fallback to
win10toast if available. Email uses Gmail SMTP with App Passwords
(the same approach as the original Security Commander).
"""

import logging
import smtplib
import socket
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List

from .events import SecurityEvent, Severity

logger = logging.getLogger(__name__)

try:
    from plyer import notification as _plyer
    HAS_PLYER = True
except ImportError:
    HAS_PLYER = False

SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc3545",
    Severity.HIGH:     "#fd7e14",
    Severity.MEDIUM:   "#ffc107",
    Severity.LOW:      "#17a2b8",
    Severity.INFO:     "#6c757d",
}

SEVERITY_BADGE_COLORS = {
    Severity.CRITICAL: "#dc3545",
    Severity.HIGH:     "#e36209",
    Severity.MEDIUM:   "#856404",
    Severity.LOW:      "#0c5460",
    Severity.INFO:     "#495057",
}


class Notifier:
    def __init__(self, config: dict):
        self._email_cfg = config.get("email", {})
        self._toast_enabled = config.get("notifications", {}).get("toast", True)

    # ------------------------------------------------------------------

    def toast(self, title: str, message: str, severity: Severity = Severity.INFO):
        """Fire a Windows desktop notification."""
        if not self._toast_enabled:
            return
        if HAS_PLYER:
            try:
                _plyer.notify(
                    title=f"Security Commander — {title}",
                    message=message[:256],
                    app_name="Security Commander",
                    timeout=8,
                )
                return
            except Exception as exc:
                logger.debug("plyer toast failed: %s", exc)

    def send_email_report(self, events: List[SecurityEvent],
                          subject: str = None) -> bool:
        """Send an HTML email report. Returns True on success."""
        sender = self._email_cfg.get("sender", "")
        password = self._email_cfg.get("app_password", "")
        if not sender or not password:
            logger.debug("Email not configured — skipping report")
            return False

        hostname = socket.gethostname()
        subject = subject or (
            f"Security Commander Report — {hostname} — "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M')}"
        )
        recipient = self._email_cfg.get("recipient", sender)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = recipient
        msg.attach(MIMEText(self._build_html(events, hostname), "html"))

        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                smtp.login(sender, password)
                smtp.send_message(msg)
            logger.info("Email report sent to %s", recipient)
            return True
        except Exception as exc:
            logger.error("Email send failed: %s", exc)
            return False

    # ------------------------------------------------------------------

    def _build_html(self, events: List[SecurityEvent], hostname: str) -> str:
        critical = sum(1 for e in events if e.severity == Severity.CRITICAL)
        high = sum(1 for e in events if e.severity == Severity.HIGH)
        medium = sum(1 for e in events if e.severity == Severity.MEDIUM)

        rows = ""
        for ev in sorted(events, key=lambda e: e.timestamp, reverse=True):
            color = SEVERITY_COLORS.get(ev.severity, "#6c757d")
            badge_bg = SEVERITY_BADGE_COLORS.get(ev.severity, "#6c757d")
            fixed = " &#10003;" if ev.remediated else ""
            rows += (
                f"<tr>"
                f"<td style='white-space:nowrap;color:#555;font-size:12px'>"
                f"  {ev.timestamp.strftime('%H:%M:%S')}</td>"
                f"<td><span style='background:{badge_bg};color:white;padding:2px 7px;"
                f"border-radius:3px;font-size:11px;font-weight:600'>"
                f"{ev.severity.value}</span></td>"
                f"<td style='font-family:monospace;font-size:12px;color:{color}'>"
                f"{ev.event_type.value}</td>"
                f"<td style='font-size:13px'>{ev.source[:24]}</td>"
                f"<td style='font-size:13px'>{ev.description[:100]}{fixed}</td>"
                f"</tr>\n"
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
  body {{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
         margin:24px;color:#212529;background:#f8f9fa}}
  h2   {{color:#2c3e50;margin-bottom:4px}}
  .summary {{background:white;padding:14px 18px;border-radius:6px;
             border-left:4px solid #2c3e50;margin-bottom:18px;
             box-shadow:0 1px 3px rgba(0,0,0,.1)}}
  table {{border-collapse:collapse;width:100%;background:white;
          border-radius:6px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
  th    {{background:#2c3e50;color:white;padding:10px 12px;text-align:left;
          font-size:13px;font-weight:600}}
  td    {{padding:7px 12px;border-bottom:1px solid #dee2e6;vertical-align:middle}}
  tr:hover {{background:#f1f3f5}}
</style>
</head>
<body>
<h2>Security Commander — {hostname}</h2>
<div class="summary">
  <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}&nbsp;&nbsp;
  <strong>Total events:</strong> {len(events)}&nbsp;&nbsp;
  <strong style="color:#dc3545">CRITICAL: {critical}</strong>&nbsp;&nbsp;
  <strong style="color:#fd7e14">HIGH: {high}</strong>&nbsp;&nbsp;
  <strong style="color:#856404">MEDIUM: {medium}</strong>
</div>
<table>
  <tr>
    <th>Time</th><th>Severity</th><th>Type</th>
    <th>Source</th><th>Description</th>
  </tr>
  {rows}
</table>
</body>
</html>"""
