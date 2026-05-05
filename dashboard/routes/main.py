# dashboard/routes/main.py
from flask import Blueprint, render_template
import sqlite3
import os

main_bp = Blueprint('main', __name__)
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'dfir.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@main_bp.route('/')
def index():
    conn = get_db()
    cursor = conn.cursor()
    
    # Summary stats
    stats = {}
    
    # Total alerts
    cursor.execute("SELECT COUNT(*) FROM alerts")
    stats['total_alerts'] = cursor.fetchone()[0]
    
    # Alerts by severity
    cursor.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
    severity_rows = cursor.fetchall()
    severity_map = {row['severity']: row['cnt'] for row in severity_rows}
    stats['critical'] = severity_map.get('CRITICAL', 0)
    stats['high']     = severity_map.get('HIGH', 0)
    stats['medium']   = severity_map.get('MEDIUM', 0)
    stats['low']      = severity_map.get('LOW', 0)
    
    # Total IOCs
    cursor.execute("SELECT COUNT(*) FROM iocs")
    stats['total_iocs'] = cursor.fetchone()[0]
    
    # Malicious IOCs
    cursor.execute("SELECT COUNT(*) FROM iocs WHERE threat_score > 50")
    stats['malicious_iocs'] = cursor.fetchone()[0]
    
    # Correlation groups
    cursor.execute("SELECT COUNT(DISTINCT group_id) FROM correlation_groups")
    stats['correlation_groups'] = cursor.fetchone()[0]
    
    # Network events
    cursor.execute("SELECT COUNT(*) FROM network_events")
    stats['network_events'] = cursor.fetchone()[0]
    
    # Recent alerts (last 10)
    cursor.execute("""
        SELECT * FROM alerts 
        ORDER BY timestamp DESC 
        LIMIT 10
    """)
    recent_alerts = cursor.fetchall()
    
    # Top threat IPs from IOCs
    cursor.execute("""
        SELECT indicator, indicator_type, threat_score, source
        FROM iocs 
        WHERE threat_score > 0
        ORDER BY threat_score DESC 
        LIMIT 5
    """)
    top_threats = cursor.fetchall()
    
    # Timeline summary
    cursor.execute("SELECT COUNT(*) FROM timeline_events")
    stats['timeline_events'] = cursor.fetchone()[0]
    
    conn.close()
    
    return render_template('index.html', 
                           stats=stats, 
                           recent_alerts=recent_alerts,
                           top_threats=top_threats)
