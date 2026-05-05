# dashboard/routes/iocs.py
from flask import Blueprint, render_template, request
import sqlite3
import os

iocs_bp = Blueprint('iocs', __name__)
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'dfir.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@iocs_bp.route('/')
def iocs():
    conn = get_db()
    cursor = conn.cursor()
    
    ioc_type_filter = request.args.get('type', 'ALL')
    search_query    = request.args.get('search', '')
    
    query = "SELECT * FROM iocs WHERE 1=1"
    params = []
    
    if ioc_type_filter != 'ALL':
        query += " AND indicator_type = ?"
        params.append(ioc_type_filter)
    
    if search_query:
        query += " AND (indicator LIKE ? OR source LIKE ?)"
        params.extend([f'%{search_query}%', f'%{search_query}%'])
    
    query += " ORDER BY threat_score DESC, timestamp DESC"
    cursor.execute(query, params)
    iocs_data = cursor.fetchall()
    
    # IOC type counts
    cursor.execute("SELECT indicator_type, COUNT(*) as cnt FROM iocs GROUP BY indicator_type")
    type_counts = {row['indicator_type']: row['cnt'] for row in cursor.fetchall()}
    
    conn.close()
    
    return render_template('iocs.html',
                           iocs=iocs_data,
                           ioc_type_filter=ioc_type_filter,
                           search_query=search_query,
                           type_counts=type_counts)
