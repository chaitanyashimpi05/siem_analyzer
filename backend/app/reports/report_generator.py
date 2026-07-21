import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "reports")
os.makedirs(REPORT_DIR, exist_ok=True)


def generate_html_report(alerts: list, stats: dict, top_ips: list) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"siem_security_report_{timestamp}.html"
    filepath = os.path.join(REPORT_DIR, filename)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SIEM Executive Security Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
        .header {{ border-bottom: 2px solid #3b82f6; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }}
        h1 {{ color: #60a5fa; margin: 0; font-size: 28px; }}
        .meta {{ color: #94a3b8; font-size: 14px; margin-top: 5px; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: #1e293b; padding: 20px; border-radius: 8px; border: 1px solid #334155; text-align: center; }}
        .card-val {{ font-size: 32px; font-weight: bold; margin-top: 10px; }}
        .critical {{ color: #ef4444; }} .high {{ color: #f97316; }} .medium {{ color: #eab308; }} .low {{ color: #3b82f6; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; font-size: 14px; }}
        th {{ background-color: #334155; color: #f8fafc; font-weight: 600; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge-critical {{ background: #7f1d1d; color: #fca5a5; }}
        .badge-high {{ background: #7c2d12; color: #fdba74; }}
        .badge-medium {{ background: #713f12; color: #fde047; }}
        .badge-low {{ background: #1e3a8a; color: #93c5fd; }}
        .section-title {{ color: #93c5fd; margin-top: 40px; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>Security Information & Event Management (SIEM)</h1>
            <div class="meta">Executive Incident Summary & Threat Analysis Report</div>
        </div>
        <div class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    </div>

    <div class="grid">
        <div class="card"><div>Total Alerts</div><div class="card-val">{stats.get('total', 0)}</div></div>
        <div class="card"><div>Critical Severity</div><div class="card-val critical">{stats.get('critical', 0)}</div></div>
        <div class="card"><div>High Severity</div><div class="card-val high">{stats.get('high', 0)}</div></div>
        <div class="card"><div>Medium Severity</div><div class="card-val medium">{stats.get('medium', 0)}</div></div>
    </div>

    <h2 class="section-title">Top Attacking IP Addresses</h2>
    <table>
        <thead><tr><th>Source IP Address</th><th>Total Alert Count</th><th>Action State</th></tr></thead>
        <tbody>
            {"".join(f"<tr><td>{ip.get('ip')}</td><td>{ip.get('count')}</td><td><span class='badge badge-critical'>FLAGGED</span></td></tr>" for ip in top_ips[:5]) or "<tr><td colspan='3'>No suspicious IP activity recorded.</td></tr>"}
        </tbody>
    </table>

    <h2 class="section-title">Recent Threat Alerts & MITRE ATT&CK Mapping</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Severity</th>
                <th>Attack Type</th>
                <th>Source IP</th>
                <th>MITRE Technique</th>
                <th>Description</th>
            </tr>
        </thead>
        <tbody>
            {"".join(f'''<tr>
                <td>{a.get("timestamp")}</td>
                <td><span class="badge badge-{a.get("severity", "low").lower()}">{a.get("severity")}</span></td>
                <td>{a.get("attack_type")}</td>
                <td>{a.get("source_ip")}</td>
                <td>{a.get("mitre_technique_id")} ({a.get("mitre_technique_name")})</td>
                <td>{a.get("description")}</td>
            </tr>''' for a in alerts[:20])}
        </tbody>
    </table>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)

    return filename


def generate_pdf_report(alerts: list, stats: dict, top_ips: list) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"siem_security_report_{timestamp}.pdf"
    filepath = os.path.join(REPORT_DIR, filename)

    doc = SimpleDocTemplate(filepath, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=20, leading=24, textColor=colors.HexColor("#1e3a8a"))
    subtitle_style = ParagraphStyle('SubTitleStyle', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor("#64748b"), spaceAfter=15)
    section_style = ParagraphStyle('SectionStyle', parent=styles['Heading2'], fontSize=14, leading=18, textColor=colors.HexColor("#1e293b"), spaceBefore=15, spaceAfter=10)
    body_style = ParagraphStyle('BodyStyle', parent=styles['Normal'], fontSize=9, leading=12, textColor=colors.HexColor("#334155"))

    elements = []
    elements.append(Paragraph("Enterprise SIEM Threat & Incident Report", title_style))
    elements.append(Paragraph(f"Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Confidential Security Assessment", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=15))

    elements.append(Paragraph("Executive Summary Statistics", section_style))
    stats_data = [
        ["Total Alerts", "Critical Alerts", "High Alerts", "Medium Alerts", "Low Alerts"],
        [str(stats.get('total', 0)), str(stats.get('critical', 0)), str(stats.get('high', 0)), str(stats.get('medium', 0)), str(stats.get('low', 0))]
    ]
    stats_table = Table(stats_data, colWidths=[100, 100, 100, 100, 100])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("Top Attacking IP Addresses", section_style))
    ip_data = [["Source IP Address", "Alert Count", "Status"]]
    for ip in top_ips[:5]:
        ip_data.append([ip.get("ip"), str(ip.get("count")), "FLAGGED"])
    if len(ip_data) == 1:
        ip_data.append(["No suspicious IPs detected", "0", "CLEAN"])

    ip_table = Table(ip_data, colWidths=[200, 150, 150])
    ip_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
    ]))
    elements.append(ip_table)
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("Detailed Security Alerts & MITRE ATT&CK Mapping", section_style))
    alert_table_data = [["Timestamp", "Severity", "Attack Type", "Source IP", "MITRE ID"]]
    for a in alerts[:15]:
        alert_table_data.append([
            a.get("timestamp", "")[:19],
            a.get("severity", ""),
            a.get("attack_type", "")[:20],
            a.get("source_ip", ""),
            a.get("mitre_technique_id", "")
        ])

    alert_table = Table(alert_table_data, colWidths=[110, 65, 130, 100, 80])
    alert_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('FONTSIZE', (0,0), (-1,-1), 8),
    ]))
    elements.append(alert_table)

    doc.build(elements)
    return filename
