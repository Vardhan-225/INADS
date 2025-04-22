from flask import Blueprint, request, jsonify
import mysql.connector
from flask_detection.config import MYSQL_CONFIG

blueprint = Blueprint("log_routes", __name__)

@blueprint.route("/all", methods=["GET"])
def get_all_logs():
    print("🛰️ Flask Blueprint: /all route HIT → Returning logs.")
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM logs ORDER BY detected_at DESC")
    logs = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(logs)

@blueprint.route("/filter", methods=["POST"])
def filter_logs():
    data = request.get_json()
    pred = data.get("pred")
    true = data.get("true")
    attack_type = data.get("attack_type")
    start_date = data.get("start")
    end_date = data.get("end")

    query = "SELECT * FROM logs WHERE 1=1"
    params = []

    if pred is not None:
        query += " AND label_pred = %s"
        params.append(pred)
    if true is not None:
        query += " AND label_true = %s"
        params.append(true)
    if attack_type:
        query += " AND original_label LIKE %s"
        params.append(f"%{attack_type}%")
    if start_date and end_date:
        query += " AND detected_at BETWEEN %s AND %s"
        params.extend([start_date, end_date])

    conn = mysql.connector.connect(**MYSQL_CONFIG)
    cursor = conn.cursor(dictionary=True)
    cursor.execute(query, params)
    logs = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(logs)

@blueprint.route("/summary", methods=["GET"])
def logs_summary():
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) as total_attacks FROM logs WHERE label_pred = 1")
    total = cursor.fetchone()["total_attacks"]

    cursor.execute("SELECT COUNT(*) as ddos FROM logs WHERE original_label LIKE '%DDoS%'")
    ddos = cursor.fetchone()["ddos"]

    cursor.execute("SELECT COUNT(*) as dos FROM logs WHERE original_label LIKE '%DoS%'")
    dos = cursor.fetchone()["dos"]

    cursor.close()
    conn.close()
    return jsonify({
        "total": total,
        "ddos": ddos,
        "dos": dos
    })

# This blueprint handles /api/logs routes: /all, /filter, /summary
detect_log_blueprint = blueprint
