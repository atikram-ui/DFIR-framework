import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from flask import Blueprint, render_template, request
from database.db_manager import get_db_connection

timeline_bp = Blueprint('timeline', __name__)

@timeline_bp.route('/timeline')
def timeline():
    conn = get_db_connection()
    cursor = conn.cursor()

    ip_filter = request.args.get('ip', '')

    try:
        query = """
            SELECT event_time, event_type, source_ip, destination_ip,
                   description, severity, source_module
            FROM timeline_events WHERE 1=1
        """
        params = []

        if ip_filter:
            query += " AND (source_ip = ? OR destination_ip = ?)"
            params.extend([ip_filter, ip_filter])

        query += " ORDER BY event_time ASC"
        cursor.execute(query, params)
        events = cursor.fetchall()

        cursor.execute("""
            SELECT DISTINCT source_ip FROM timeline_events
            WHERE source_ip IS NOT NULL AND source_ip != ''
        """)
        unique_ips = [row[0] for row in cursor.fetchall()]
    except Exception as e:
        events = []
        unique_ips = []

    conn.close()
    return render_template('timeline.html',
        events=events,
        ip_filter=ip_filter,
        unique_ips=unique_ips
    )
