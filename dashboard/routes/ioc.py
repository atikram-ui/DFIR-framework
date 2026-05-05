import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from flask import Blueprint, render_template, request
from database.db_manager import get_db_connection

ioc_bp = Blueprint('ioc', __name__)

@ioc_bp.route('/ioc')
def ioc():
    conn = get_db_connection()
    cursor = conn.cursor()

    ioc_type_filter = request.args.get('type', '')
    search = request.args.get('search', '')

    try:
        query = """
            SELECT i.id, i.ioc_type, i.ioc_value, i.first_seen, i.last_seen,
                   t.threat_score, t.malicious_count, t.country, t.isp, t.tags
            FROM iocs i
            LEFT JOIN threat_intel t ON i.ioc_value = t.ioc_value
            WHERE 1=1
        """
        params = []

        if ioc_type_filter:
            query += " AND i.ioc_type = ?"
            params.append(ioc_type_filter)

        if search:
            query += " AND i.ioc_value LIKE ?"
            params.append(f'%{search}%')

        query += " ORDER BY i.last_seen DESC"
        cursor.execute(query, params)
        iocs = cursor.fetchall()

        cursor.execute("SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type")
        type_counts = dict(cursor.fetchall())
    except Exception as e:
        iocs = []
        type_counts = {}

    conn.close()
    return render_template('ioc.html',
        iocs=iocs,
        type_counts=type_counts,
        ioc_type_filter=ioc_type_filter,
        search=search
    )
