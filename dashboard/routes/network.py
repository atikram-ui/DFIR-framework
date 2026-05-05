import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from flask import Blueprint, render_template, request
from database.db_manager import get_db_connection

network_bp = Blueprint('network', __name__)

@network_bp.route('/network')
def network():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT source_ip, COUNT(*) as count
            FROM network_packets
            GROUP BY source_ip ORDER BY count DESC LIMIT 10
        """)
        top_src_ips = cursor.fetchall()

        cursor.execute("""
            SELECT protocol, COUNT(*) as count
            FROM network_packets GROUP BY protocol
        """)
        protocols = cursor.fetchall()

        page = int(request.args.get('page', 1))
        per_page = 25
        offset = (page - 1) * per_page

        cursor.execute("""
            SELECT source_ip, dest_ip, protocol, source_port,
                   dest_port, packet_size, timestamp
            FROM network_packets
            ORDER BY timestamp DESC LIMIT ? OFFSET ?
        """, (per_page, offset))
        packets = cursor.fetchall()

        cursor.execute("SELECT COUNT(*) FROM network_packets")
        total = cursor.fetchone()[0]

        cursor.execute("""
            SELECT source_ip, COUNT(DISTINCT dest_port) as port_count
            FROM network_packets
            GROUP BY source_ip HAVING port_count > 10
            ORDER BY port_count DESC
        """)
        port_scanners = cursor.fetchall()

    except Exception as e:
        top_src_ips = []
        protocols = []
        packets = []
        total = 0
        port_scanners = []
        page = 1

    total_pages = max(1, (total + per_page - 1) // per_page) if total > 0 else 1

    conn.close()
    return render_template('network.html',
        top_src_ips=top_src_ips,
        protocols=protocols,
        packets=packets,
        page=page,
        total_pages=total_pages,
        total=total,
        port_scanners=port_scanners
    )
