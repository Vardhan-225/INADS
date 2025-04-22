from flask import Flask, request, jsonify
from flask_cors import CORS
from detection_utils import run_detection_pipeline
from config import MYSQL_CONFIG
import mysql.connector
import os

app = Flask(__name__)
CORS(app)

# Set up MySQL connection (basic example)
db_conn = mysql.connector.connect(
    host=MYSQL_CONFIG["host"],
    user=MYSQL_CONFIG["user"],
    password=MYSQL_CONFIG["password"],
    database=MYSQL_CONFIG["database"]
)

@app.route("/status", methods=["GET"])
def status():
    return jsonify({"status": "Detection server is running."})

@app.route("/detect")
def detect():
    print("➡️ /detect endpoint triggered")
    try:
        output = run_detection_pipeline()
        print("✔️ Pipeline executed, result count:", len(output))
        if not isinstance(output, list) or not isinstance(output[0], dict):
            print("⚠️ Unexpected result structure from pipeline")
            raise ValueError("run_detection_pipeline() must return a list of dictionaries.")

        results = output

        # Persist current run into anomalies table
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor()
        # Clear old logs
        cursor.execute("TRUNCATE TABLE anomalies")
        # Insert new results
        insert_query = """
            INSERT INTO anomalies 
              (idx, global_conf, edge_conf, device_conf, fused_score, label_pred, label_true, original_label)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        for r in results:
            cursor.execute(insert_query, (
                r["index"],
                r["global_conf"],
                r["edge_conf"],
                r["device_conf"],
                r["fused_score"],
                r["predicted_label"],
                r["true_label"],
                r.get("original_label", "Unknown")
            ))
        conn.commit()
        cursor.close()
        conn.close()

        print(f"✅ Returning {len(results[:10])} results after DB update")
        return jsonify(results[:10])  # Return first 10
    except Exception as e:
        import traceback
        print("❌ DETECTION SERVER ERROR:")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/logs/anomalies", methods=["GET"])
def get_logs():
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM anomalies ORDER BY detected_at DESC LIMIT 1000")
        logs = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(logs)
    except Exception as e:
        import traceback
        print("❌ ERROR FETCHING LOGS:")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

from detect_and_log import detect_log_blueprint
app.register_blueprint(detect_log_blueprint, url_prefix="/api/logs")

if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", "5001"))
    app.run(debug=True, host="0.0.0.0", port=5001)