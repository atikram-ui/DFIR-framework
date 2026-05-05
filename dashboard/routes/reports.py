import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from flask import Blueprint, Response, request, send_file
from database.db_manager import get_db_connection
import csv, io
from datetime import datetime

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/report/csv')
def download_csv():
    conn = get_db_connection()
    cursor = conn.cursor()
    report_type = request.args.get('type', 'alerts')

    output = io.StringIO()
    writer = csv.writer(output)

    if report_type == 'alerts':
        writer.writerow(['ID', 'Type', 'Severity', 'Source IP', 'Description', 'Timestamp'])
        cursor.execute("SELECT id, alert_type, severity, source_ip, description, timestamp FROM alerts ORDER BY timestamp DESC")
        for row in cursor.fetchall():
            writer.writerow(row)

    elif report_type == 'ioc':
        writer.writerow(['ID', 'IOC Type', 'IOC Value', 'First Seen', 'Last Seen'])
        try:
            cursor.execute("SELECT id, ioc_type, ioc_value, first_seen, last_seen FROM iocs")
            for row in cursor.fetchall():
                writer.writerow(row)
        except:
            writer.writerow(['No IOC data available'])

    elif report_type == 'timeline':
        writer.writerow(['Time', 'Event Type', 'Source IP', 'Dest IP', 'Description', 'Severity'])
        try:
            cursor.execute("SELECT event_time, event_type, source_ip, destination_ip, description, severity FROM timeline_events ORDER BY event_time")
            for row in cursor.fetchall():
                writer.writerow(row)
        except:
            writer.writerow(['No timeline data available'])

    conn.close()
    output.seek(0)
    filename = f"dfir_{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

@reports_bp.route('/report/pdf')
def download_pdf():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.units import inch
    except ImportError:
        return "ReportLab not installed. Run: pip install reportlab", 500

    conn = get_db_connection()
    cursor = conn.cursor()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('CustomTitle', parent=styles['Title'],
                                  fontSize=20, textColor=colors.darkblue)
    elements.append(Paragraph("DFIR Correlation Framework", title_style))
    elements.append(Paragraph("Incident Investigation Report", styles['Heading2']))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Executive Summary", styles['Heading1']))
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'")
    critical = cursor.fetchone()[0]

    try:
        cursor.execute("SELECT COUNT(*) FROM iocs")
        total_iocs = cursor.fetchone()[0]
    except:
        total_iocs = 0

    try:
        cursor.execute("SELECT COUNT(*) FROM correlations")
        total_corr = cursor.fetchone()[0]
    except:
        total_corr = 0

    summary_data = [
        ['Metric', 'Count'],
        ['Total Alerts', str(total_alerts)],
        ['Critical Alerts', str(critical)],
        ['Total IOCs', str(total_iocs)],
        ['Correlations Detected', str(total_corr)],
    ]
    t = Table(summary_data, colWidths=[3*inch, 2*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.lightgrey]),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Critical & High Alerts", styles['Heading1']))
    cursor.execute("""
        SELECT alert_type, severity, source_ip, description, timestamp
        FROM alerts WHERE severity IN ('CRITICAL','HIGH')
        ORDER BY timestamp DESC LIMIT 20
    """)
    alert_rows = cursor.fetchall()
    alert_data = [['Type', 'Severity', 'Source IP', 'Description', 'Time']]
    for row in alert_rows:
        desc = str(row[3])[:40] + '...' if row[3] and len(str(row[3])) > 40 else str(row[3] or '')
        alert_data.append([str(row[0] or ''), str(row[1] or ''), str(row[2] or 'N/A'), desc, str(row[4] or '')[:16]])

    if len(alert_data) > 1:
        at = Table(alert_data, colWidths=[1.2*inch, 0.8*inch, 1.2*inch, 2.2*inch, 1.1*inch])
        at.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.red),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.lightyellow]),
        ]))
        elements.append(at)

    conn.close()
    doc.build(elements)
    buffer.seek(0)

    filename = f"DFIR_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(buffer, mimetype='application/pdf',
                     as_attachment=True, download_name=filename)
