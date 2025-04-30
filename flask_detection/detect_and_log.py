from flask import Blueprint, request, jsonify
import mysql.connector
from flask_detection.config import MYSQL_CONFIG
import logging

bp = Blueprint("detect_log", __name__)

@bp.route("/top10", methods=["GET"])
def top10_logs():
    logging.info("Received request for /top10")
    conn = None
    cur = None
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT * FROM logs
            ORDER BY fused_score DESC
            LIMIT %s
        """, (10,))
        top10 = cur.fetchall()
        logging.info("Fetched top 10 logs successfully")
        return jsonify(top10)
    except mysql.connector.Error as e:
        logging.error(f"Database error on /top10: {e}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        logging.error(f"Unexpected error on /top10: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@bp.route("/preview", methods=["GET"])
def preview_logs():
    return top10_logs()

@bp.route("/all")
def all_logs():
    limit = request.args.get("limit", default=100, type=int)
    logging.info(f"Received request for /all with limit={limit}")
    conn = None
    cur = None
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM logs ORDER BY detected_at DESC LIMIT %s", (limit,))
        data = cur.fetchall()
        logging.info(f"Fetched {len(data)} logs successfully")
        return jsonify(data)
    except mysql.connector.Error as e:
        logging.error(f"Database error on /all: {e}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        logging.error(f"Unexpected error on /all: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@bp.route("/summary")
def summary():
    logging.info("Received request for /summary")
    conn = None
    cur = None
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT COUNT(*) AS total FROM logs WHERE label_pred = 1")
        total = cur.fetchone()["total"]
        cur.execute("SELECT COUNT(*) AS dos FROM logs WHERE original_label LIKE %s AND original_label NOT LIKE %s AND label_pred = 1", ("%DoS attacks%", "%DDoS%",))
        dos = cur.fetchone()["dos"]
        cur.execute("SELECT COUNT(*) AS ddos FROM logs WHERE original_label LIKE %s AND label_pred = 1", ("%DDoS attacks%",))
        ddos = cur.fetchone()["ddos"]
        logging.info("Fetched summary successfully")
        return jsonify({"total": total, "dos": dos, "ddos": ddos})
    except mysql.connector.Error as e:
        logging.error(f"Database error on /summary: {e}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        logging.error(f"Unexpected error on /summary: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@bp.route("/anomalies", methods=["GET"])
def anomalies():
    logging.info("Received request for /anomalies")
    conn = None
    cur = None
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM logs WHERE label_pred = %s ORDER BY detected_at DESC", (1,))
        anomalies = cur.fetchall()
        logging.info(f"Fetched {len(anomalies)} anomalies successfully")
        return jsonify(anomalies)
    except mysql.connector.Error as e:
        logging.error(f"Database error on /anomalies: {e}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        logging.error(f"Unexpected error on /anomalies: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@bp.route("/timeline", methods=["GET"])
def anomaly_timeline():
    logging.info("Received request for /timeline")
    conn = None
    cur = None
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT 
                DATE_FORMAT(detected_at, '%H:%i:%s') AS time_bucket,
                COUNT(*) AS count
            FROM logs
            WHERE label_pred = 1
            GROUP BY time_bucket
            ORDER BY time_bucket ASC
        """)
        timeline = cur.fetchall()
        return jsonify(timeline)
    except mysql.connector.Error as e:
        logging.error(f"Database error on /timeline: {e}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        logging.error(f"Unexpected error on /timeline: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@bp.route("/top10_attacks", methods=["GET"])
def top10_attacks():
    logging.info("Received request for /logs/top10_attacks")
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT original_label AS attack, COUNT(*) AS count
            FROM logs
            WHERE label_pred = 1
            GROUP BY original_label
            ORDER BY count DESC
            LIMIT 10
        """)
        data = cur.fetchall()
        return jsonify(data)
    except Exception as e:
        logging.error(f"Error in /logs/top10_attacks: {e}")
        return jsonify([]), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

@bp.route("/filter", methods=["POST"])
def filter_logs():
    logging.info("Received request for /logs/filter")
    payload = request.get_json()

    draw = payload.get("draw", 1)
    start = payload.get("start", 0)
    length = payload.get("length", 100)

    fid = payload.get("id")
    pred = payload.get("pred")
    truth = payload.get("true")
    atk = payload.get("attack_type")
    start_dt = payload.get("start")
    end_dt = payload.get("end")

    where, params = ["1=1"], []

    if fid is not None:
        where.append("id = %s")
        params.append(fid)
    if pred in ("0", "1"):
        where.append("label_pred = %s")
        params.append(pred)
    if truth in ("0", "1"):
        where.append("label_true = %s")
        params.append(truth)
    if atk:
        where.append("original_label = %s")
        params.append(atk)
    if start_dt:
        where.append("detected_at >= %s")
        params.append(start_dt)
    if end_dt:
        where.append("detected_at <= %s")
        params.append(end_dt)

    where_clause = " AND ".join(where)

    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cur = conn.cursor(dictionary=True)

        cur.execute("SELECT COUNT(*) AS cnt FROM logs")
        records_total = cur.fetchone()["cnt"]

        cur.execute(f"SELECT COUNT(*) AS cnt FROM logs WHERE {where_clause}", params)
        records_filtered = cur.fetchone()["cnt"]

        query = f"""
            SELECT * FROM logs WHERE {where_clause}
            ORDER BY detected_at DESC
            LIMIT %s OFFSET %s
        """
        cur.execute(query, params + [length, start])
        data = cur.fetchall()

        return jsonify({
            "draw": draw,
            "recordsTotal": records_total,
            "recordsFiltered": records_filtered,
            "data": data
        })

    except mysql.connector.Error as e:
        logging.error(f"Database error on /logs/filter: {e}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        logging.error(f"Unexpected error on /logs/filter: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()
        
detect_log_blueprint = bp