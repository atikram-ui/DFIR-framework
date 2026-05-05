import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from flask import Blueprint, render_template, request
from database.db_manager import get_db_connection

correlation_bp = Blueprint('correlation', __name__)

@correlation_bp.route('/correlation')
def correlation():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT id, source_ip, attack_stage, event_count,
                   first_seen, last_seen, description
            FROM correlations ORDER BY event_count DESC
        """)
        correlations = cursor.fetchall()
    except Exception as e:
        correlations = []

    correlation_details = []
    for corr in correlations:
        corr_id, source_ip, attack_stage, event_count, first_seen, last_seen, desc = corr
        cursor.execute("""
            SELECT alert_type, severity, description, timestamp
            FROM alerts WHERE source_ip = ?
            ORDER BY timestamp ASC LIMIT 10
        """, (source_ip,))
        related_alerts = cursor.fetchall()
        correlation_details.append({
            'id': corr_id,
            'source_ip': source_ip,
            'attack_stage': attack_stage,
            'event_count': event_count,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'description': desc,
            'alerts': related_alerts
        })

    conn.close()
    return render_template('correlation.html', correlations=correlation_details)
