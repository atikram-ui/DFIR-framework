import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from flask import Blueprint, render_template, request
from database.db_manager import get_db_connection

alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('/alerts')
def alerts():
    conn = get_db_connection()
    cursor = conn.cursor()

    severity_filter = request.args.get('severity', '')
    search_query = request.args.get('search', '')
    page = int(request.args.get('page', 1))
    per_page = 20
    offset = (page - 1) * per_page

    query = "SELECT id, alert_type, severity, source_ip, description, timestamp FROM alerts WHERE 1=1"
    params = []

    if severity_filter:
        query += " AND severity = ?"
        params.append(severity_filter)

    if search_query:
        query += " AND (description LIKE ? OR source_ip LIKE ? OR alert_type LIKE ?)"
        params.extend([f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'])

    count_query = query.replace(
        "SELECT id, alert_type, severity, source_ip, description, timestamp",
        "SELECT COUNT(*)"
    )
    cursor.execute(count_query, params)
    total = cursor.fetchone()[0]

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    cursor.execute(query, params)
    alerts_list = cursor.fetchall()

    cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
    severity_counts = dict(cursor.fetchall())

    conn.close()

    total_pages = (total + per_page - 1) // per_page

    return render_template('alerts.html',
        alerts=alerts_list,
        severity_filter=severity_filter,
        search_query=search_query,
        severity_counts=severity_counts,
        page=page,
        total_pages=total_pages,
        total=total
    )
