"""
EmailService — reads ALL SMTP config from environment variables.
Frontend never sees SMTP credentials — it only provides recipient addresses.
"""

import os
import asyncio
import smtplib
import ssl as _ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from email.mime.base      import MIMEBase
from email                import encoders
from typing               import List, Tuple, Optional


class EmailService:

    def __init__(self):
        self.host       = os.getenv("SMTP_HOST",  "smtp.gmail.com")
        self.port       = int(os.getenv("SMTP_PORT", "587"))
        self.user       = os.getenv("SMTP_USER",  "")
        self.password   = os.getenv("SMTP_PASS",  "")
        self.from_email = os.getenv("FROM_EMAIL", self.user)
        self.from_name  = os.getenv("FROM_NAME",  "PQC Scanner")

    def is_configured(self) -> bool:
        return bool(self.user and self.password)

    async def send_report(
        self,
        to:              List[str],
        subject:         str,
        body_html:       str,
        attachment_path: Optional[str] = None,
        attachment_name: Optional[str] = None,
    ) -> Tuple[bool, str]:
        if not self.is_configured():
            return False, "SMTP not configured — set SMTP_USER and SMTP_PASS in .env"
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._send_sync, to, subject, body_html, attachment_path, attachment_name
        )

    def _send_sync(self, to, subject, body_html, attachment_path, attachment_name):
        try:
            msg            = MIMEMultipart("mixed")
            msg["Subject"] = subject
            msg["From"]    = f"{self.from_name} <{self.from_email}>"
            msg["To"]      = ", ".join(to)

            alt = MIMEMultipart("alternative")
            alt.attach(MIMEText("PQC Scanner Report — view in HTML client.", "plain"))
            alt.attach(MIMEText(body_html, "html"))
            msg.attach(alt)

            if attachment_path and os.path.exists(attachment_path):
                with open(attachment_path, "rb") as f:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(f.read())
                encoders.encode_base64(part)
                fname = attachment_name or os.path.basename(attachment_path)
                part.add_header("Content-Disposition", f'attachment; filename="{fname}"')
                msg.attach(part)

            ctx = _ssl.create_default_context()
            if self.port == 465:
                with smtplib.SMTP_SSL(self.host, self.port, context=ctx, timeout=30) as s:
                    s.login(self.user, self.password)
                    s.sendmail(self.from_email, to, msg.as_string())
            else:
                with smtplib.SMTP(self.host, self.port, timeout=30) as s:
                    s.ehlo(); s.starttls(context=ctx); s.ehlo()
                    s.login(self.user, self.password)
                    s.sendmail(self.from_email, to, msg.as_string())
            return True, f"Sent to {', '.join(to)}"
        except smtplib.SMTPAuthenticationError:
            return False, "SMTP auth failed — check SMTP_USER and SMTP_PASS in .env"
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"

    def build_report_email(self, scan: dict, fmt: str) -> str:
        summary = scan.get("summary", {})
        domain  = scan.get("domain", "")
        risk    = summary.get("quantum_risk_score", 0)
        color   = "#16a34a" if risk <= 20 else "#d97706" if risk <= 60 else "#dc2626"
        return f"""
        <html><body style="font-family:system-ui,sans-serif;max-width:580px;margin:0 auto;color:#1a1a18">
          <div style="background:#1a1a18;padding:28px 32px;border-radius:10px 10px 0 0">
            <div style="font-family:monospace;font-size:11px;color:#6b6b64;letter-spacing:.1em;text-transform:uppercase;margin-bottom:8px">PQC CBOM Scanner</div>
            <h2 style="color:#fff;margin:0;font-weight:400;font-size:20px">Quantum Readiness Report</h2>
            <div style="color:#6b6b64;font-size:13px;margin-top:4px">{domain}</div>
          </div>
          <div style="background:#f7f7f5;padding:28px 32px;border-radius:0 0 10px 10px;border:1px solid #e8e8e4;border-top:none">
            <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
              <tr><td style="padding:8px 0;color:#6b6b64;font-size:13px">Hosts Scanned</td><td style="font-weight:500">{summary.get('total_hosts',0)}</td></tr>
              <tr><td style="padding:8px 0;color:#6b6b64;font-size:13px">TLS Endpoints</td><td style="font-weight:500">{summary.get('tls_endpoints',0)}</td></tr>
              <tr><td style="padding:8px 0;color:#16a34a;font-size:13px">Fully Quantum Safe</td><td style="font-weight:500;color:#16a34a">{summary.get('fully_quantum_safe',0)}</td></tr>
              <tr><td style="padding:8px 0;color:#0c4a6e;font-size:13px">PQC Ready</td><td style="font-weight:500;color:#0c4a6e">{summary.get('pqc_ready',0)}</td></tr>
              <tr><td style="padding:8px 0;color:#854d0e;font-size:13px">PQC Not Ready</td><td style="font-weight:500;color:#854d0e">{summary.get('pqc_not_ready',0)}</td></tr>
              <tr><td style="padding:8px 0;color:#991b1b;font-size:13px">Not Quantum Safe</td><td style="font-weight:500;color:#991b1b">{summary.get('not_quantum_safe',0)}</td></tr>
              <tr style="border-top:1px solid #e8e8e4">
                <td style="padding:12px 0 4px;font-weight:600">Quantum Risk Score</td>
                <td style="font-size:24px;font-weight:700;color:{color}">{risk}<span style="font-size:14px;font-weight:400">/100</span></td>
              </tr>
            </table>
            <p style="font-size:12px;color:#9f9f96">Full {fmt.upper()} report attached · PQC CBOM Scanner v2.0 · NIST FIPS 203/204/205</p>
          </div>
        </html>"""
