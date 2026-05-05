# dashboard/routes/api.py
from flask import Blueprint, jsonify
import sqlite3
import os
from collections import defaultdict

api_bp = Blueprint('api', __name__)
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'dfir.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@api_bp.route('/alerts/severity')
def alerts_severity():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
    data = {row['severity']: row['cnt'] for row in cursor.fetchall()}
    conn.close()
    return jsonify({
        'labels': list(data.keys()),
        'values': list(data.values()),
        'colors': {
            'CRITICAL': '#dc3545',
            'HIGH':     '#fd7e14',
            'MEDIUM':   '#ffc107',
            'LOW':      '#28a745'
        }
    })

@api_bp.route('/alerts/timeline')
def alerts_timeline():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT DATE(timestamp) as day, COUNT(*) as cnt 
        FROM alerts 
        GROUP BY DATE(timestamp) 
        ORDER BY day ASC
        LIMIT 30
    """)
    rows = cursor.fetchall()
    conn.close()
    return jsonify({
        'labels': [row['day'] for row in rows],
        'values': [row['cnt'] for row in rows]
    })

@api_bp.route('/iocs/types')
def iocs_types():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT indicator_type, COUNT(*) as cnt FROM iocs GROUP BY indicator_type")
    data = {row['indicator_type']: row['cnt'] for row in cursor.fetchall()}
    conn.close()
    return jsonify({
        'labels': list(data.keys()),
        'values': list(data.values())
    })

@api_bp.route('/network/protocols')
def network_protocols():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT protocol, COUNT(*) as cnt FROM network_events GROUP BY protocol")
    data = {row['protocol']: row['cnt'] for row in cursor.fetchall()}
    conn.close()
    return jsonify({
        'labels': list(data.keys()),
        'values': list(data.values())
    })

@api_bp.route('/alerts/by_module')
def alerts_by_module():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT source_module, COUNT(*) as cnt 
        FROM alerts 
        GROUP BY source_module
    """)
    data = {row['source_module']: row['cnt'] for row in cursor.fetchall()}
    conn.close()
    return jsonify({
        'labels': list(data.keys()),
        'values': list(data.values())
    })

@api_bp.route('/summary')
def summary():
    conn = get_db()
    cursor = conn.cursor()
    
    result = {}
    
    cursor.execute("SELECT COUNT(*) FROM alerts")
    result['total_alerts'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM iocs")
    result['total_iocs'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM network_events")
    result['network_events'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(DISTINCT group_id) FROM correlation_groups")
    result['correlation_groups'] = cursor.fetchone()[0]
    
    conn.close()
    return jsonify(result)
