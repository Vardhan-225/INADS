# flask_detection/detection_server.py

import time, traceback
from flask       import Flask, jsonify
from flask_cors  import CORS
import mysql.connector

from flask_detection.config           import MYSQL_CONFIG, BATCH_INSERT_SIZE, SLEEP_INTERVAL_SEC
from flask_detection.detection_utils  import run_detection_pipeline
from flask_detection.detect_and_log   import detect_log_blueprint

app = Flask(__name__)
from flask_cors import CORS

CORS(app, supports_credentials=True, origins=["http://localhost:3000"])
app.register_blueprint(detect_log_blueprint, url_prefix="/api/logs")

@app.route("/status")
def status():
    return jsonify({"status":"Detection server running"})

@app.route("/detect", methods=["POST"])
def detect():
    print(f"➡️ Detection start | batch={BATCH_INSERT_SIZE}, sleep={SLEEP_INTERVAL_SEC}")
    conn   = mysql.connector.connect(**MYSQL_CONFIG)
    cursor = conn.cursor(prepared=True)
    conn.start_transaction()

    cursor.execute("TRUNCATE TABLE logs")
    print("🧹 logs cleared")

    SQL = ("INSERT INTO logs "
           "(idx, global_conf, edge_conf, device_conf, fused_score,"
           " label_pred, label_true, original_label) "
           "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)")

    total, preview = 0, []
    buf = []

    try:
        for rec in run_detection_pipeline():
            total += 1
            buf.append((
                rec["index"], rec["global_conf"], rec["edge_conf"],
                rec["device_conf"], rec["fused_score"],
                rec["predicted_label"], rec["true_label"], rec["original_label"]
            ))
            if len(preview)<10: preview.append(rec)
            if len(buf)>=BATCH_INSERT_SIZE:
                cursor.executemany(SQL, buf)
                conn.commit()
                print(f"✅ inserted {len(buf)} rows")
                buf.clear()
                time.sleep(SLEEP_INTERVAL_SEC)

        if buf:
            cursor.executemany(SQL, buf)
            conn.commit()
            print(f"✅ inserted final {len(buf)} rows")

        print("✔️ Done:", total, "rows")
        return jsonify({"count":total, "preview":preview})

    except Exception as e:
        conn.rollback()
        print("↩️ rollback on error")
        traceback.print_exc()
        return jsonify({"error":str(e)}), 500

    finally:
        cursor.close(); conn.close()
        print("🔒 DB closed")

@app.route("/api/core-detection", methods=["POST"])
def core_detection_alias():
    return detect()

if __name__=="__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)